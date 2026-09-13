from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nerd_mcp import credentials
from nerd_mcp.cli import main
from nerd_mcp.inventory import InventoryError


@pytest.fixture
def backend(monkeypatch):
    for name in ("NERD_DEFAULT_USERNAME", "NERD_DEFAULT_PASSWORD", "CISCO_DEFAULT_USERNAME", "CISCO_DEFAULT_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(credentials.sys, "platform", "win32")
    api = SimpleNamespace(CRED_TYPE_GENERIC=1, CRED_PERSIST_LOCAL_MACHINE=2,
                          CredRead=Mock(), CredWrite=Mock(), CredDelete=Mock())
    monkeypatch.setattr(credentials, "windows_backend", lambda: api)
    return api


def test_saved_unicode_credentials(backend):
    backend.CredRead.return_value = {"UserName": "operator", "CredentialBlob": "pássword".encode("utf-16-le")}
    assert credentials.resolve_credentials("DEFAULT") == ("operator", "pássword", "Windows Credential Manager")
    backend.CredRead.assert_called_once_with("nerd-mcp:default", 1)


def test_complete_environment_takes_precedence(backend, monkeypatch):
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "env-user")
    monkeypatch.setenv("NERD_DEFAULT_PASSWORD", "env-pass")
    assert credentials.resolve_credentials("default") == ("env-user", "env-pass", "environment")
    backend.CredRead.assert_not_called()


def test_partial_environment_never_mixes_sources(backend, monkeypatch):
    monkeypatch.setenv("NERD_DEFAULT_USERNAME", "env-user")
    backend.CredRead.return_value = {"UserName": "stored-user", "CredentialBlob": "stored-pass"}
    assert credentials.resolve_credentials("default")[:2] == ("stored-user", "stored-pass")


def test_missing_credential_has_actionable_error(backend):
    error = OSError("not found")
    error.winerror = 1168
    backend.CredRead.side_effect = error
    with pytest.raises(InventoryError, match="credentials set default"):
        credentials.resolve_credentials("default")


def test_backend_error_is_sanitized(backend):
    backend.CredRead.side_effect = RuntimeError("secret backend detail")
    with pytest.raises(InventoryError) as error:
        credentials.resolve_credentials("default")
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("profile", ["../default", "default;reload", "", "a-b"])
def test_invalid_profile_rejected(backend, profile):
    with pytest.raises(InventoryError):
        credentials.resolve_credentials(profile)
    backend.CredRead.assert_not_called()


def test_interactive_save(backend, monkeypatch, capsys):
    monkeypatch.setattr(credentials.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "operator")
    monkeypatch.setattr(credentials.getpass, "getpass", lambda _: "private-value")
    credentials.save_interactive("default")
    record = backend.CredWrite.call_args.args[0]
    assert record["TargetName"] == "nerd-mcp:default"
    assert record["Persist"] == 2
    assert record["CredentialBlob"] == "private-value"
    assert "private-value" not in capsys.readouterr().out


def test_mismatch_does_not_write(backend, monkeypatch):
    monkeypatch.setattr(credentials.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "operator")
    monkeypatch.setattr(credentials.getpass, "getpass", Mock(side_effect=["one", "two"]))
    with pytest.raises(InventoryError, match="do not match"):
        credentials.save_interactive("default")
    backend.CredWrite.assert_not_called()


def test_noninteractive_entry_rejected(backend, monkeypatch):
    monkeypatch.setattr(credentials.sys.stdin, "isatty", lambda: False)
    with pytest.raises(InventoryError, match="interactive"):
        credentials.save_interactive("default")
    backend.CredWrite.assert_not_called()


def test_status_never_prints_credentials(backend, capsys):
    backend.CredRead.return_value = {"UserName": "private-user", "CredentialBlob": "private-pass"}
    assert main(["credentials", "status", "default"]) == 0
    output = capsys.readouterr().out
    assert "Windows Credential Manager" in output
    assert "private-user" not in output and "private-pass" not in output


def test_delete_only_selected_profile(backend):
    credentials.remove_saved("branch")
    assert [c.args for c in backend.CredDelete.call_args_list] == [("nerd-mcp:branch", 1), ("cisco-mcp:branch", 1)]


def test_noninteractive_save_accepts_collected_values(backend):
    credentials.save_saved("branch", " operator ", "private-value")
    record = backend.CredWrite.call_args.args[0]
    assert record["TargetName"] == "nerd-mcp:branch"
    assert record["UserName"] == "operator"
    assert record["CredentialBlob"] == "private-value"


def test_cli_collects_credentials_before_calling_store(backend, monkeypatch, capsys):
    monkeypatch.setattr(credentials.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "operator")
    monkeypatch.setattr(
        credentials.getpass, "getpass",
        Mock(side_effect=["private-value", "private-value"]),
    )

    assert main(["--no-footer", "credentials", "set", "default"]) == 0
    record = backend.CredWrite.call_args.args[0]
    assert record["UserName"] == "operator"
    assert record["CredentialBlob"] == "private-value"
    assert "private-value" not in capsys.readouterr().out
