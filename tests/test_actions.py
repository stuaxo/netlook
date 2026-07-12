"""Unit tests for netlook.core.actions."""
from dataclasses import dataclass

import pytest

from netlook.core import actions
from netlook.core.actions import (
    CredentialAction,
    IncusConsoleAction,
    RemoteSessionAction,
    ShareAction,
    SftpBrowseAction,
    WebAdminAction,
    display_name,
)
from netlook.core.services import IncusInstance, SmbShare

from doubles import FakeScanner


@dataclass
class _FakeService:
    """A minimal stand-in for core.models.Service - just the attributes Action
    factories actually read. Using this instead of the real dataclass proves
    actions.py's claim that it has no runtime dependency on models.py."""
    kind: str
    ip: str
    port: int


@pytest.mark.parametrize("kind, expected", [
    ("ssh", "Secure Shell (SSH)"),
    ("rdp", "Remote Desktop (RDP)"),
    ("incus", "Incus"),
    ("some-new-thing", "Some New Thing"),
])
def test_display_name_maps_known_kinds_and_titlecases_unknown_ones(kind, expected):
    """Verify that display_name returns the curated PROTOCOL_NAMES entry for a known
    kind, and falls back to a title-cased version of the raw kind otherwise, by
    checking both a listed and an unlisted kind."""
    result = display_name(kind)

    assert result == expected


def test_remote_session_action_from_service_builds_a_scheme_uri_and_readable_label():
    """Verify that RemoteSessionAction.from_service builds a scheme://ip:port uri and
    a human-readable label, by checking both against an ssh-kind fake service."""
    service = _FakeService(kind="ssh", ip="10.0.0.5", port=22)

    action = RemoteSessionAction.from_service(service)

    assert action.uri == "ssh://10.0.0.5:22"
    assert action.label == "Secure Shell (SSH)"


async def test_remote_session_action_run_prefers_remmina_when_installed(monkeypatch, popen_calls):
    """Verify that RemoteSessionAction.run launches via remmina when it's installed,
    by monkeypatching HAS_REMMINA True and checking the resulting Popen command."""
    monkeypatch.setattr(actions, "HAS_REMMINA", True)
    action = RemoteSessionAction(label="ssh", uri="ssh://10.0.0.5:22")

    await action.run(scanner=None)

    assert popen_calls == [["remmina", "-c", "ssh://10.0.0.5:22"]]


async def test_remote_session_action_run_falls_back_to_xdg_open_without_remmina(monkeypatch, popen_calls):
    """Verify that RemoteSessionAction.run falls back to xdg-open when remmina isn't
    installed, by monkeypatching HAS_REMMINA False and checking the Popen command."""
    monkeypatch.setattr(actions, "HAS_REMMINA", False)
    action = RemoteSessionAction(label="ssh", uri="ssh://10.0.0.5:22")

    await action.run(scanner=None)

    assert popen_calls == [["xdg-open", "ssh://10.0.0.5:22"]]


@pytest.mark.parametrize("port_override, expected_port", [
    (None, 8443),    # falls back to the service's own detected port
    (47990, 47990),  # explicit override, e.g. Sunshine's config UI
])
def test_web_admin_action_from_service_honors_the_port_override(port_override, expected_port):
    """Verify that WebAdminAction.from_service uses the service's own port unless an
    explicit override is given, by comparing the built uri's port for both cases."""
    service = _FakeService(kind="incus", ip="10.0.0.5", port=8443)

    action = WebAdminAction.from_service(service, path="/ui/", scheme="https", port=port_override)

    assert action.uri == f"https://10.0.0.5:{expected_port}/ui/"


def test_share_action_from_resource_builds_an_smb_uri_labeled_with_the_share_name():
    """Verify that ShareAction.from_resource builds an smb:// uri for the given
    share and labels the button with the share's own name, by checking both fields."""
    service = _FakeService(kind="smb", ip="10.0.0.5", port=445)

    action = ShareAction.from_resource(service, SmbShare("Public"))

    assert action.uri == "smb://10.0.0.5/Public"
    assert action.label == "Public"


def test_incus_console_action_from_resource_labels_with_name_and_status():
    """Verify that IncusConsoleAction.from_resource labels the button with the
    instance's name and status, by checking a running-instance example."""
    service = _FakeService(kind="incus", ip="10.0.0.5", port=8443)
    instance = IncusInstance("web-vm", "Running")

    action = IncusConsoleAction.from_resource(service, instance)

    assert action.label == "web-vm (Running)"
    assert action.uri == "https://10.0.0.5:8443/ui/"


@pytest.mark.parametrize("user, path, port, expected_uri", [
    ("", "", 22, "sftp://10.0.0.5"),
    ("bob", "/home/bob", 22, "sftp://bob@10.0.0.5/home/bob"),
    ("bob", "srv", 2222, "sftp://bob@10.0.0.5:2222/srv"),
    ("", "  /data  ", 22, "sftp://10.0.0.5/data"),
])
async def test_sftp_browse_action_run_normalizes_user_path_and_port(popen_calls, user, path, port, expected_uri):
    """Verify that SftpBrowseAction.run builds a correct sftp:// uri across
    combinations of user/path/port, by checking it adds a leading slash to a bare
    path, omits the default port 22, and strips surrounding whitespace."""
    action = SftpBrowseAction(ip="10.0.0.5", port=port)

    await action.run(scanner=None, user=user, path=path)

    assert popen_calls == [["xdg-open", expected_uri]]


async def test_credential_action_run_re_queries_the_owning_service_via_scanner():
    """Verify that CredentialAction.run calls scanner.request_items with the trimmed
    username and the owning service, by capturing the call on a fake scanner."""
    service = _FakeService(kind="smb", ip="10.0.0.5", port=445)
    action = CredentialAction.from_service(service)
    scanner = FakeScanner()

    await action.run(scanner, user="  bob  ", password="secret")

    assert scanner.requested == [(service, {"user": "bob", "password": "secret"})]
