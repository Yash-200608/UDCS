"""Pure decision logic: classification, hysteresis, policy merging, presence."""

import itertools

import pytest

from udcs_agent.governor.classifier import Assessment, Hysteresis, Signals, classify
from udcs_agent.governor.interactive import HelperReports, InteractiveMonitor
from udcs_agent.winplat.sessions import Session, WTSActive, WTSDisconnected
from udcs_shared.protection import (
    InteractiveState,
    ProtectionLevel,
    ProtectionPolicy,
    stricter,
)

L, S = ProtectionLevel, InteractiveState
GiB = 2**30
POLICY = ProtectionPolicy()


def sig(**overrides) -> Signals:
    base = dict(
        cpu_total_percent=10.0,
        cpu_udcs_percent=5.0,
        memory_total_bytes=16 * GiB,
        memory_available_bytes=10 * GiB,
        memory_udcs_bytes=GiB,
        interactive=S.NO_USER,
        hard_faults_per_second=0.0,
        disk_busy_percent=5.0,
        gpu_other_percent=0.0,
        gpu_udcs_percent=0.0,
    )
    base.update(overrides)
    return Signals(**base)


@pytest.mark.parametrize(
    ("interactive", "expected"),
    [
        (S.NO_USER, L.OPEN),
        (S.LOCKED, L.AWAY),
        (S.IDLE, L.AWAY),
        (S.ACTIVE, L.SHARED),
    ],
)
def test_presence_sets_the_baseline_level(interactive, expected):
    assert classify(sig(interactive=interactive), POLICY).level == expected


def test_login_alone_does_not_stop_cpu_work():
    """The operating model: a logged-in student does not by itself stop UDCS."""
    level = classify(sig(interactive=S.ACTIVE), POLICY).level
    assert level == L.SHARED and POLICY.envelopes[level].cpu_cap_percent > 0


def test_udcs_load_is_not_mistaken_for_student_load():
    # 90% total CPU, but 85% of it is UDCS itself: no pressure.
    assert classify(sig(cpu_total_percent=90, cpu_udcs_percent=85), POLICY).level == L.OPEN
    # Same total, mostly someone else: pressure.
    pressured = classify(sig(cpu_total_percent=90, cpu_udcs_percent=5), POLICY)
    assert pressured.level == L.CONSTRAINED and "cpu_pressure" in pressured.reasons


def test_away_requires_a_quiet_machine():
    """Idle input is not idle demand: a locked PC rendering a video is not 'away'."""
    busy = classify(sig(interactive=S.LOCKED, cpu_total_percent=35, cpu_udcs_percent=0), POLICY)
    assert busy.level == L.SHARED and "background_activity" in busy.reasons


@pytest.mark.parametrize(
    "overrides",
    [
        {"memory_available_bytes": int(0.15 * 16 * GiB)},
        {"hard_faults_per_second": 900.0},
    ],
)
def test_memory_pressure_constrains_even_without_a_user(overrides):
    assert classify(sig(**overrides), POLICY).level == L.CONSTRAINED


def test_memory_critical_flag():
    a = classify(sig(memory_available_bytes=int(0.05 * 16 * GiB)), POLICY)
    assert a.memory_critical and "memory_critical" in a.reasons


def test_presentation_mode_protects():
    assert (
        classify(sig(interactive=S.ACTIVE, protected_presentation=True), POLICY).level
        == L.PROTECTED
    )


def test_disk_and_gpu_flags():
    a = classify(sig(interactive=S.ACTIVE, disk_busy_percent=90, gpu_other_percent=40), POLICY)
    assert a.disk_pressure and a.gpu_demand
    # Disk pressure is about the student: it does not stop disk work on an empty machine.
    assert not classify(sig(interactive=S.NO_USER, disk_busy_percent=90), POLICY).disk_pressure


def test_missing_measurements_fail_toward_the_student():
    a = classify(sig(collection_error="PdhError"), POLICY)
    assert a.level == L.CONSTRAINED and a.gpu_demand and a.disk_pressure
    assert classify(sig(gpu_other_percent=None), POLICY).gpu_demand
    assert classify(sig(interactive=S.ACTIVE, disk_busy_percent=None), POLICY).disk_pressure


def test_maintenance_overrides_everything():
    assert classify(sig(maintenance=True), POLICY).level == L.MAINTENANCE


# -- hysteresis -----------------------------------------------------------------------------


def _assess(level):
    return Assessment(level, ())


def test_escalation_is_immediate_relaxation_is_slow():
    policy = ProtectionPolicy(relax_after_seconds=30, post_activity_grace_seconds=0)
    h = Hysteresis(level=L.OPEN)
    assert h.update(_assess(L.CONSTRAINED), S.ACTIVE, 0.0, policy) == L.CONSTRAINED
    for t in (1, 10, 29):
        assert h.update(_assess(L.OPEN), S.NO_USER, float(t), policy) == L.CONSTRAINED
    assert h.update(_assess(L.OPEN), S.NO_USER, 31.0, policy) == L.OPEN


def test_flapping_pressure_does_not_cause_flapping_actions():
    policy = ProtectionPolicy(relax_after_seconds=30, post_activity_grace_seconds=0)
    h = Hysteresis(level=L.OPEN)
    levels = []
    for t in range(120):  # pressure every 10 s for 1 s
        target = L.CONSTRAINED if t % 10 == 0 else L.OPEN
        levels.append(h.update(_assess(target), S.NO_USER, float(t), policy))
    switches = sum(1 for a, b in itertools.pairwise(levels) if a != b)
    assert switches == 0 and levels[-1] == L.CONSTRAINED


def test_relaxes_to_the_strictest_calm_level_seen():
    policy = ProtectionPolicy(relax_after_seconds=10, post_activity_grace_seconds=0)
    h = Hysteresis(level=L.CONSTRAINED)
    h.update(_assess(L.OPEN), S.NO_USER, 0.0, policy)
    h.update(_assess(L.SHARED), S.ACTIVE, 5.0, policy)
    assert h.update(_assess(L.OPEN), S.NO_USER, 11.0, policy) == L.SHARED


def test_post_activity_grace_keeps_shared_after_unlock():
    policy = ProtectionPolicy(relax_after_seconds=5, post_activity_grace_seconds=120)
    h = Hysteresis(level=L.OPEN)
    h.update(_assess(L.OPEN), S.LOCKED, 0.0, policy)
    assert h.update(_assess(L.OPEN), S.ACTIVE, 1.0, policy) == L.SHARED  # unlock
    assert h.update(_assess(L.OPEN), S.ACTIVE, 100.0, policy) == L.SHARED
    h.update(_assess(L.OPEN), S.ACTIVE, 122.0, policy)
    assert h.update(_assess(L.OPEN), S.ACTIVE, 128.0, policy) == L.OPEN


# -- policy merge ----------------------------------------------------------------------------


def test_controller_policy_can_only_tighten_the_local_floor():
    local = ProtectionPolicy()
    shared = local.envelopes[L.SHARED].model_copy(
        update={"cpu_cap_percent": 100, "allow_memory_class": True}
    )
    loose = ProtectionPolicy(
        version=7,
        min_available_memory_percent=5,
        critical_available_memory_percent=2,
        other_cpu_constrained_percent=95,
        relax_after_seconds=5,
        envelopes={**local.envelopes, L.SHARED: shared},
    )
    merged = ProtectionPolicy.strictest(local, loose)
    assert merged.min_available_memory_percent == local.min_available_memory_percent
    assert merged.other_cpu_constrained_percent == local.other_cpu_constrained_percent
    assert merged.relax_after_seconds == local.relax_after_seconds
    assert merged.envelopes[L.SHARED].cpu_cap_percent == 50
    assert merged.envelopes[L.SHARED].allow_memory_class is False
    assert merged.version == 7
    tight = ProtectionPolicy(other_cpu_constrained_percent=20, other_cpu_relax_percent=15)
    assert ProtectionPolicy.strictest(local, tight).other_cpu_constrained_percent == 20


def test_inconsistent_policy_is_rejected():
    with pytest.raises(ValueError):
        ProtectionPolicy(min_available_memory_percent=10, critical_available_memory_percent=20)


def test_stricter_ordering():
    assert stricter(L.OPEN, L.CONSTRAINED) == L.CONSTRAINED
    assert stricter(L.MAINTENANCE, L.SHARED) == L.MAINTENANCE


# -- interactive monitor (fail-safe presence) -------------------------------------------------


def _monitor(sessions, reports=None, clock=lambda: 0.0):
    reports = reports or HelperReports(clock=clock)
    return InteractiveMonitor(
        reports, idle_after_seconds=lambda: 300, list_sessions=lambda: sessions
    ), reports


def test_no_interactive_session_is_no_user():
    m, _ = _monitor([Session(2, False, WTSDisconnected, None)])
    assert m() == (S.NO_USER, False)


def test_all_locked_is_locked():
    m, _ = _monitor([Session(1, True, WTSActive, True)])
    assert m() == (S.LOCKED, False)


def test_unlocked_without_helper_report_is_active():
    m, _ = _monitor([Session(1, True, WTSActive, False)])
    assert m() == (S.ACTIVE, False)


def test_unknown_lock_state_counts_as_unlocked():
    m, _ = _monitor([Session(1, True, WTSActive, None)])
    assert m()[0] == S.ACTIVE


def test_idle_requires_every_unlocked_session_to_be_idle():
    now = [0.0]
    m, reports = _monitor(
        [Session(1, True, WTSActive, False), Session(3, False, WTSActive, False)],
        clock=lambda: now[0],
    )
    reports.update(1, idle_seconds=900, notification_state=5)
    assert m()[0] == S.ACTIVE  # session 3 has no report
    reports.update(3, idle_seconds=901, notification_state=5)
    assert m()[0] == S.IDLE
    now[0] = 11.0  # reports go stale
    assert m()[0] == S.ACTIVE


def test_fullscreen_or_presentation_protects():
    m, reports = _monitor([Session(1, True, WTSActive, False)])
    reports.update(1, idle_seconds=0, notification_state=3)
    assert m() == (S.ACTIVE, True)


def test_malformed_helper_reports_are_ignored():
    m, reports = _monitor([Session(1, True, WTSActive, False)])
    reports.update(1, idle_seconds=-5, notification_state=5)
    reports.update(1, idle_seconds=900, notification_state=99)
    assert m()[0] == S.ACTIVE


def test_session_query_failure_is_active():
    def broken():
        raise OSError("WTS unavailable")

    m = InteractiveMonitor(HelperReports(), idle_after_seconds=lambda: 300, list_sessions=broken)
    assert m() == (S.ACTIVE, False)


# -- threshold hysteresis (enter / exit thresholds, smoothing) -------------------------------


def test_cpu_spikes_do_not_constrain_when_the_smoothed_load_is_moderate():
    """Antivirus-style 1 s spikes over 50% must not trigger (or keep) CONSTRAINED."""
    spiky = sig(cpu_total_percent=70, cpu_udcs_percent=0, cpu_non_udcs_smoothed_percent=42)
    assert classify(spiky, POLICY).level == L.OPEN


def test_severe_instantaneous_load_acts_without_waiting_for_smoothing():
    severe = sig(cpu_total_percent=96, cpu_udcs_percent=0, cpu_non_udcs_smoothed_percent=20)
    assert classify(severe, POLICY).level == L.CONSTRAINED


def test_enter_and_exit_thresholds_differ():
    def at(smoothed, latched=frozenset()):
        s = sig(
            cpu_total_percent=smoothed, cpu_udcs_percent=0, cpu_non_udcs_smoothed_percent=smoothed
        )
        return classify(s, POLICY, latched).level

    pressure = frozenset({"cpu_pressure"})
    assert at(55) == L.CONSTRAINED  # enter above 50
    assert at(45) == L.OPEN  # below enter: not constrained
    assert at(45, pressure) == L.CONSTRAINED  # but once pressure is latched, stay above 35
    assert at(30, pressure) == L.OPEN  # leave only below 35
    # A cautious *start-up* CONSTRAINED level must not latch the exit threshold:
    assert at(45, frozenset({"signals_unavailable"})) == L.OPEN


def test_memory_exit_threshold_has_a_margin():
    total = 16 * GiB
    s = sig(memory_available_bytes=int(0.22 * total))  # 22%: above enter (20) ...
    assert classify(s, POLICY).level == L.OPEN
    latched = frozenset({"memory_pressure"})
    assert classify(s, POLICY, latched).level == L.CONSTRAINED  # ... below exit (25)


def test_relax_threshold_cannot_exceed_enter_threshold():
    with pytest.raises(ValueError):
        ProtectionPolicy(other_cpu_constrained_percent=40, other_cpu_relax_percent=45)


def test_strictest_merges_exit_thresholds_protectively():
    tight = ProtectionPolicy(other_cpu_relax_percent=20, memory_relax_margin_percent=10)
    merged = ProtectionPolicy.strictest(ProtectionPolicy(), tight)
    assert merged.other_cpu_relax_percent == 20 and merged.memory_relax_margin_percent == 10


# -- regressions from the adversarial review ---------------------------------------------------


def test_maintenance_wins_over_a_signal_error():
    a = classify(sig(maintenance=True, collection_error="PdhError"), POLICY)
    assert a.level == L.MAINTENANCE


def test_presentation_still_protects_when_signals_fail():
    a = classify(sig(collection_error="PdhError", protected_presentation=True), POLICY)
    assert a.level == L.PROTECTED


def test_disk_pressure_ignored_for_an_idle_session():
    """An idle/locked session must not see UDCS's own disk I/O as student pressure."""
    assert not classify(sig(interactive=S.IDLE, disk_busy_percent=95), POLICY).disk_pressure
    assert classify(sig(interactive=S.ACTIVE, disk_busy_percent=95), POLICY).disk_pressure


def test_helper_report_from_before_an_unlock_is_ignored():
    now = [0.0]
    sessions = [Session(1, True, WTSActive, True)]
    reports = HelperReports(clock=lambda: now[0])
    monitor = InteractiveMonitor(
        reports, idle_after_seconds=lambda: 300, list_sessions=lambda: sessions
    )
    reports.update(1, idle_seconds=900, notification_state=5)  # idle while locked
    assert monitor()[0] == S.LOCKED
    now[0] = 2.0
    sessions[0] = Session(1, True, WTSActive, False)  # the student unlocks
    assert monitor()[0] == S.ACTIVE, "a pre-unlock 'idle' report must not count"
    now[0] = 4.0
    reports.update(1, idle_seconds=1.0, notification_state=5)
    assert monitor()[0] == S.ACTIVE
