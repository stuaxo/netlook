"""Unit tests for netlook.core.actions."""
import pytest

from netlook.core import actions
from netlook.core.actions import LaunchAction, SftpBrowseAction, display_name


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


async def test_launch_action_run_prefers_remmina_when_opener_is_remmina_and_installed(monkeypatch, popen_calls):
    """Verify that LaunchAction.run launches via remmina when opener="remmina" and
    remmina is installed, by monkeypatching HAS_REMMINA True and checking the
    resulting Popen command."""
    monkeypatch.setattr(actions, "HAS_REMMINA", True)
    action = LaunchAction(label="ssh", uri="ssh://10.0.0.5:22", opener="remmina")

    await action.run(scanner=None)

    assert popen_calls == [["remmina", "-c", "ssh://10.0.0.5:22"]]


async def test_launch_action_run_falls_back_to_xdg_open_without_remmina(monkeypatch, popen_calls):
    """Verify that LaunchAction.run falls back to xdg-open when opener="remmina" but
    remmina isn't installed, by monkeypatching HAS_REMMINA False and checking the
    Popen command."""
    monkeypatch.setattr(actions, "HAS_REMMINA", False)
    action = LaunchAction(label="ssh", uri="ssh://10.0.0.5:22", opener="remmina")

    await action.run(scanner=None)

    assert popen_calls == [["xdg-open", "ssh://10.0.0.5:22"]]


async def test_launch_action_run_uses_xdg_open_for_the_default_opener_even_with_remmina_installed(
    monkeypatch, popen_calls,
):
    """Verify that LaunchAction.run only ever prefers remmina for opener="remmina" -
    the default opener ("xdg-open", used by every non-remote-session builder) should
    never launch remmina even when it's installed."""
    monkeypatch.setattr(actions, "HAS_REMMINA", True)
    action = LaunchAction(label="Incus admin", uri="https://10.0.0.5:8443/ui/")

    await action.run(scanner=None)

    assert popen_calls == [["xdg-open", "https://10.0.0.5:8443/ui/"]]


async def test_launch_action_run_uses_gtk_launch_for_smb_uris_when_gio_open_is_the_handler(
    monkeypatch, popen_calls,
):
    """Verify that LaunchAction.run routes smb:// shares through gtk-launch with the
    default inode/directory handler when xdg-open would resolve to gio open - gio open
    can't open a share that GVfs hasn't mounted yet, but the file manager mounts it on
    demand when launched directly with the uri."""
    monkeypatch.setattr(actions, "_uses_gio_open", lambda: True)
    monkeypatch.setattr(actions, "_default_file_manager", lambda: "org.gnome.Nautilus.desktop")
    action = LaunchAction(label="stuff", uri="smb://10.0.0.5/stuff")

    await action.run(scanner=None)

    assert popen_calls == [["gtk-launch", "org.gnome.Nautilus.desktop", "smb://10.0.0.5/stuff"]]


async def test_launch_action_run_uses_xdg_open_for_smb_uris_when_gio_open_is_not_the_handler(
    monkeypatch, popen_calls,
):
    """Verify that LaunchAction.run falls back to plain xdg-open for smb:// shares on
    desktops (e.g. KDE) whose xdg-open doesn't route through gio open."""
    monkeypatch.setattr(actions, "_uses_gio_open", lambda: False)
    action = LaunchAction(label="stuff", uri="smb://10.0.0.5/stuff")

    await action.run(scanner=None)

    assert popen_calls == [["xdg-open", "smb://10.0.0.5/stuff"]]


async def test_launch_action_run_falls_back_to_xdg_open_when_no_default_file_manager_is_registered(
    monkeypatch, popen_calls,
):
    """Verify that LaunchAction.run falls back to xdg-open for an smb:// share even
    when gio open is the handler, if xdg-mime has no inode/directory default to
    gtk-launch."""
    monkeypatch.setattr(actions, "_uses_gio_open", lambda: True)
    monkeypatch.setattr(actions, "_default_file_manager", lambda: None)
    action = LaunchAction(label="stuff", uri="smb://10.0.0.5/stuff")

    await action.run(scanner=None)

    assert popen_calls == [["xdg-open", "smb://10.0.0.5/stuff"]]


@pytest.mark.parametrize("user, path, port, expected_uri", [
    ("", "", 22, "sftp://10.0.0.5"),
    ("bob", "/home/bob", 22, "sftp://bob@10.0.0.5/home/bob"),
    ("bob", "srv", 2222, "sftp://bob@10.0.0.5:2222/srv"),
    ("", "  /data  ", 22, "sftp://10.0.0.5/data"),
])
async def test_sftp_browse_action_run_normalizes_user_path_and_port(
    monkeypatch, popen_calls, user, path, port, expected_uri,
):
    """Verify that SftpBrowseAction.run builds a correct sftp:// uri across
    combinations of user/path/port, by checking it adds a leading slash to a bare
    path, omits the default port 22, and strips surrounding whitespace. Pinned to
    the plain-xdg-open path (see the gio-open tests below for the other branch) so
    this test's own assertion is only about uri-building, not opener selection."""
    monkeypatch.setattr(actions, "_uses_gio_open", lambda: False)
    action = SftpBrowseAction(ip="10.0.0.5", port=port)

    await action.run(scanner=None, user=user, path=path)

    assert popen_calls == [["xdg-open", expected_uri]]


async def test_sftp_browse_action_run_uses_gtk_launch_when_gio_open_is_the_handler(monkeypatch, popen_calls):
    """Verify that SftpBrowseAction.run, like LaunchAction's smb:// shares, routes
    through gtk-launch with the default inode/directory handler when xdg-open would
    resolve to gio open - gio open can't open an sftp:// location GVfs hasn't
    mounted yet either, the same bug smb:// shares hit (see _open_directory)."""
    monkeypatch.setattr(actions, "_uses_gio_open", lambda: True)
    monkeypatch.setattr(actions, "_default_file_manager", lambda: "org.gnome.Nautilus.desktop")
    action = SftpBrowseAction(ip="10.0.0.5", port=22)

    await action.run(scanner=None, user="bob", path="/data")

    assert popen_calls == [["gtk-launch", "org.gnome.Nautilus.desktop", "sftp://bob@10.0.0.5/data"]]


async def test_sftp_browse_action_run_uses_xdg_open_when_gio_open_is_not_the_handler(monkeypatch, popen_calls):
    """Verify that SftpBrowseAction.run falls back to plain xdg-open on a desktop
    (e.g. KDE) whose xdg-open doesn't route through gio open."""
    monkeypatch.setattr(actions, "_uses_gio_open", lambda: False)
    action = SftpBrowseAction(ip="10.0.0.5", port=22)

    await action.run(scanner=None, user="bob", path="/data")

    assert popen_calls == [["xdg-open", "sftp://bob@10.0.0.5/data"]]
