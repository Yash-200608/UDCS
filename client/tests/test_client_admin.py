"""`udcs admin`: the operator procedure for user-code eligibility, end to end against
the real controller (in-process)."""

from __future__ import annotations

import json


def test_operator_procedure_audit_grant_and_revoke(run, h, app, tmp_path):
    node = h.SimulatedNode(app, eligible=False)
    admin = run("login", "--username", "admin")
    assert admin.code == 0, admin.err
    listed = run("admin", "nodes")
    assert listed.code == 0 and "not eligible" in listed.out

    refused = run("admin", "user-code", "allow", node.node_id, "--reason", "first try", "--yes")
    assert refused.code == 2 and "no exposure audit" in refused.err

    bad = h.synthetic_exposure_report("sim", "11", "10.0.22631")
    bad["findings"] = [{"category": "network", "target": "1.1.1.1:443", "access": "connect"}]
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    failed = run("admin", "audit-upload", node.node_id, str(tmp_path / "bad.json"))
    assert failed.code == 5 and "network reachable" in failed.out

    good = h.synthetic_exposure_report("sim", "11", "10.0.22631")
    (tmp_path / "good.json").write_text(json.dumps(good))
    passed = run("admin", "audit-upload", node.node_id, str(tmp_path / "good.json"))
    assert passed.code == 0 and "PASSED" in passed.out
    history = run("admin", "audits", node.node_id)
    assert history.out.count("\n") == 2

    granted = run("admin", "user-code", "allow", node.node_id, "--reason", "audit passed", "--yes")
    assert granted.code == 0 and "eligible for image 11|10.0.22631" in granted.out
    revoked = run("admin", "user-code", "revoke", node.node_id, "--reason", "incident 7")
    assert revoked.code == 0 and "no longer eligible" in revoked.out


def test_researchers_cannot_use_admin_commands(logged_in, h, app):
    node = h.SimulatedNode(app, eligible=False)
    result = logged_in("admin", "user-code", "revoke", node.node_id, "--reason", "not mine")
    assert result.code == 1 and "administrator" in result.err
