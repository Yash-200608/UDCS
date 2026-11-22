import sys
import uuid

import pytest

from udcs_agent.config import AgentConfig, ConfigError, load_config, save_config
from udcs_agent.credentials import CredentialStore, CredentialStoreError, NodeCredential


@pytest.mark.parametrize(
    "url",
    [
        "http://controller.campus.edu",
        "ftp://controller.campus.edu",
        "https://user:pw@controller.campus.edu",
        "https://controller.campus.edu/?x=1",
        "https://",
    ],
)
def test_unsafe_controller_urls_are_refused(url):
    with pytest.raises(ConfigError):
        AgentConfig(controller_url=url)


def test_plain_http_requires_explicit_opt_in():
    config = AgentConfig(controller_url="http://127.0.0.1:8000/", allow_insecure_http=True)
    assert config.controller_url == "http://127.0.0.1:8000"


def test_config_round_trip(tmp_path):
    ca = tmp_path / "campus ca.pem"  # spaces and backslashes must survive TOML encoding
    ca.write_text("dummy")
    original = AgentConfig(
        controller_url="https://udcs.campus.edu:8443", ca_bundle=ca, node_name='Lab "B" #3'
    )
    save_config(tmp_path, original)
    loaded = load_config(tmp_path)
    assert loaded.controller_url == original.controller_url
    assert loaded.ca_bundle.resolve() == ca.resolve()
    assert loaded.node_name == 'Lab "B" #3'


def test_missing_config_gives_actionable_error(tmp_path):
    with pytest.raises(ConfigError, match="enroll"):
        load_config(tmp_path)


def _credential():
    return NodeCredential(node_id=uuid.uuid4(), secret="udcs_n_" + "S" * 43)


def test_secret_is_not_in_repr():
    assert "SSSS" not in repr(_credential())


def test_plain_store_round_trip(tmp_path):
    store = CredentialStore(tmp_path / "cred.bin", use_dpapi=False)
    assert store.load() is None
    credential = _credential()
    store.save(credential)
    assert store.load() == credential


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_store_encrypts_at_rest(tmp_path):
    store = CredentialStore(tmp_path / "cred.bin", use_dpapi=True)
    credential = _credential()
    store.save(credential)
    raw = (tmp_path / "cred.bin").read_bytes()
    assert credential.secret.encode() not in raw
    assert str(credential.node_id).encode() not in raw
    assert store.load() == credential


def test_corrupt_store_raises_clear_error(tmp_path):
    path = tmp_path / "cred.bin"
    path.write_bytes(b"garbage")
    with pytest.raises(CredentialStoreError, match="unrecognised"):
        CredentialStore(path).load()
    path.write_bytes(b"UDCSP1\n{not json")
    with pytest.raises(CredentialStoreError):
        CredentialStore(path).load()
