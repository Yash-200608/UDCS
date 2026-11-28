"""A diagnostic is acceptance evidence only on the LocalSystem session-0 path."""

from udcs_agent.diagnostics import context


def test_interactive_run_is_never_evidence():
    wrapped = context.labelled("exposure-audit", {"passed": True}, evidence_context=True)
    assert wrapped["identity"]["context"] != "localsystem"
    assert wrapped["evidence"] is False
    assert wrapped["note"].startswith("DIAGNOSTIC ONLY")
    assert len(wrapped["machine"]["label"]) == 12  # a hash, not the host name


def test_localsystem_identity_never_records_the_machine_account(monkeypatch):
    # Measured on a real SYSTEM run: USERNAME was HOSTNAME$, which leaked the host name
    # and failed the controller's "SYSTEM" runner check.
    from udcs_agent.diagnostics import exposure_audit

    monkeypatch.setattr(context, "_sid", lambda: context.LOCAL_SYSTEM_SID)
    monkeypatch.setattr(context, "_session_id", lambda: 0)
    monkeypatch.setenv("USERNAME", "HOSTNAME$")
    assert context.execution_context()["user"] == "NT AUTHORITY\\SYSTEM"
    assert exposure_audit._runner() == "NT AUTHORITY\\SYSTEM (session 0)"
    assert "SYSTEM" in exposure_audit._runner().upper()  # what grant_user_code requires


def test_localsystem_counts_only_on_the_evidence_path(monkeypatch):
    fake = {
        "context": "localsystem",
        "is_local_system": True,
        "elevated": True,
        "session_id": 0,
        "user": "SYSTEM",
        "sid_kind": "LocalSystem",
    }
    monkeypatch.setattr(context, "execution_context", lambda: fake)
    assert context.labelled("x", {}, evidence_context=True)["evidence"] is True
    assert context.labelled("x", {}, evidence_context=False)["evidence"] is False
    fake["context"] = "localsystem-interactive-session"
    assert context.labelled("x", {}, evidence_context=True)["evidence"] is False


def test_gpu_probe_account_never_records_a_name(monkeypatch):
    # gpu_probe results land in committed acceptance evidence (M1.5 E1 matrix).
    from udcs_agent.diagnostics import context, gpu_probe

    monkeypatch.setenv("USERNAME", "LABPC-042$")
    monkeypatch.setattr(context, "_sid", lambda: context.LOCAL_SYSTEM_SID)
    assert gpu_probe._account() == r"NT AUTHORITY\SYSTEM"
    monkeypatch.setenv("USERNAME", "jstudent")
    monkeypatch.setattr(context, "_sid", lambda: "S-1-5-21-1-2-3-1001")
    assert gpu_probe._account() == "<user>"
