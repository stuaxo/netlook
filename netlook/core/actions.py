"""Actions a user can trigger from a service's row.

This is the only module that shells out to xdg-open/remmina or drives the scanner in
response to a click - Service subclasses (services.py) only ever build and yield
Action instances, they never launch anything themselves.

Kept free of any runtime dependency on models.py/scanner.py (only used in type hints,
guarded by TYPE_CHECKING) so this module can be imported and its Actions constructed
and executed with nothing else from the package - a CLI or test could do the same.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import NetworkScanner

HAS_REMMINA = shutil.which("remmina") is not None


def _uses_gio_open() -> bool:
    """Whether plain `xdg-open` will end up shelling out to `gio open` on this
    desktop. Per /usr/bin/xdg-open's open_gnome/open_gnome3/open_mate/
    open_xfce/open_generic fallbacks, that's every desktop except KDE and
    Cinnamon (which have their own scheme-aware openers, kde-open/nemo, that
    don't share gio's unmounted-share bug)."""
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
    if any(name in desktop for name in ("KDE", "Cinnamon")):
        return False
    return shutil.which("gio") is not None


def _default_file_manager() -> str | None:
    """The .desktop id xdg-mime has registered for inode/directory (e.g.
    "org.gnome.Nautilus.desktop"), for launching it directly via gtk-launch."""
    try:
        result = subprocess.run(
            ["xdg-mime", "query", "default", "inode/directory"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None

# service kind -> human-readable protocol name for row/button labels, e.g. "Secure
# Shell (SSH)" instead of a bare "ssh". Lives here (not models.py/services.py) so
# both those modules and ui/base.py can use it without a circular import - actions.py
# has no internal dependencies of its own.
PROTOCOL_NAMES = {
    "ssh": "Secure Shell (SSH)",
    "rdp": "Remote Desktop (RDP)",
    "vnc": "Screen Sharing (VNC)",
    # These four are raw protocol acronyms most users won't recognize on sight -
    # named after what they actually are, not just the technical protocol, the
    # same idea as the Printers tab's "Printer admin" wording (see
    # web_admin_action call sites in services.py, which already override
    # cups/ipp/ipps's action label separately - renaming these here only changes
    # the category tab's entry header, not any button text).
    "smb": "Windows file share (SMB)",
    "cups": "Print server (CUPS)",
    "ipp": "Network printer (IPP)",
    "ipps": "Network printer (IPPS)",
    "printer": "Print queue (LPD)",
    "pdl-datastream": "Raw Printing (JetDirect)",
    "incus": "Incus",
    "home-assistant": "Home Assistant",
    "moonlight": "Game Streaming (Moonlight)",
    "device-info": "Device Info",
    "hue": "Philips Hue",
    "workstation": "Workstation",
    # Not a real discovered kind - the shared header for a grouped category tab's
    # single combined entry (see models.GROUPED_CATEGORIES).
    "printer-group": "Printer",
}


def display_name(kind: str) -> str:
    """Falls back to a title-cased version of the raw kind for anything not listed
    in PROTOCOL_NAMES, so an as-yet-unnamed kind still reads reasonably."""
    return PROTOCOL_NAMES.get(kind, kind.replace("-", " ").title())


@dataclass
class Action:
    label: str
    fields: tuple[str, ...] = ()  # names of text inputs the UI must collect before run()

    async def run(self, scanner: "NetworkScanner", **kwargs) -> None:
        """`scanner` is an explicit context reference, not a global - every
        concrete Action here just launches an external app (a plain synchronous
        call even though this method is async), so none of them actually need it
        today; kept on the signature since a future input-driven Action might."""
        raise NotImplementedError

    @staticmethod
    def _popen(cmd: list[str]) -> None:
        print(f"Launching: {' '.join(cmd)}")
        try:
            subprocess.Popen(cmd)
        except FileNotFoundError:
            print(f"Can't run {cmd[0]}: not found")

    def _open_directory(self, uri: str) -> None:
        """Opens a GVfs directory uri (smb://, sftp://) via xdg-open, working around
        gio open's inability to open one that GVfs hasn't already mounted (see
        _uses_gio_open) by launching the default file manager directly instead - it
        mounts on demand when given the uri directly, unlike gio open. Shared by
        every Action that opens this kind of uri (LaunchAction's smb:// shares,
        SftpBrowseAction) rather than each re-implementing the same workaround."""
        if _uses_gio_open():
            file_manager = _default_file_manager()
            if file_manager:
                self._popen(["gtk-launch", file_manager, uri])
                return
        self._popen(["xdg-open", uri])


@dataclass
class LaunchAction(Action):
    """Opens a uri via the system's default handler (xdg-open), or via remmina
    (if installed) for a remote-session launch. Replaces what used to be five
    near-identical Action subclasses (RemoteSessionAction, WebAdminAction,
    ShareAction, SmbPrinterAction, IncusConsoleAction) that differed only in
    how their uri got built, never in how they ran - that construction now
    lives with whichever Service subclass owns the relevant knowledge
    (services.py), or, for the couple of builders shared across several
    unrelated kinds, as free functions in models.py."""
    uri: str = ""
    opener: str = "xdg-open"  # "remmina" for remote-session launches (ssh/rdp/vnc)

    async def run(self, scanner: "NetworkScanner") -> None:
        if self.opener == "remmina" and HAS_REMMINA:
            self._popen(["remmina", "-c", self.uri])
            return
        if self.uri.startswith("smb://"):
            self._open_directory(self.uri)
            return
        self._popen(["xdg-open", self.uri])


@dataclass
class SftpBrowseAction(Action):
    """Opens a path on an ssh host in the system file manager, over sftp:// via GVfs."""
    label: str = "browse"
    fields: tuple[str, ...] = ("user", "path")
    ip: str = ""
    port: int = 22

    async def run(self, scanner: "NetworkScanner", user: str = "", path: str = "") -> None:
        user = user.strip()
        path = path.strip()
        if path and not path.startswith("/"):
            path = f"/{path}"
        auth = f"{user}@" if user else ""
        port_part = f":{self.port}" if self.port != 22 else ""
        self._open_directory(f"sftp://{auth}{self.ip}{port_part}{path}")
