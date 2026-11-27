"""A diagnostic is acceptance evidence only on the LocalSystem session-0 path."""

from udcs_agent.diagnostics import context


def test_interactive_run_is_never_evidence():
    wrapped = context.labelled("exposure-audit", {"passed": True}, evidence_context=True)
    assert wrapped["identity"]["context"] != "localsystem"
    assert wrapped["evidence"] is False
    assert wrapped["note"].startswith("DIAGNOSTIC ONLY")
    assert len(wrapped["machine"]["label"]) == 12  # a hash, not the host name


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
