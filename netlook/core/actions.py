"""Actions a user can trigger from a service's row.

This is the only module that shells out to xdg-open/remmina or drives the scanner in
response to a click - Service subclasses (services.py) only ever build and yield
Action instances, they never launch anything themselves.

Kept free of any runtime dependency on models.py/scanner.py (only used in type hints,
guarded by TYPE_CHECKING) so this module can be imported and its Actions constructed
and executed with nothing else from the package - a CLI or test could do the same.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Service
    from .scanner import NetworkScanner

HAS_REMMINA = shutil.which("remmina") is not None
SESSION_SCHEMES = {"ssh": "ssh", "rdp": "rdp", "vnc": "vnc"}

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
    # same idea as the Printers tab's "Printer admin" wording (see WebAdminAction
    # call sites in services.py, which already override cups/ipp/ipps's action
    # label separately - renaming these here only changes the category tab's
    # entry header, not any button text).
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
        """`scanner` is an explicit context reference, not a global - actions that
        don't need it (most of them: they just launch an external app, a plain
        synchronous call even though this method is async) ignore it; actions that
        do (CredentialAction) await it to kick off a background fetch."""
        raise NotImplementedError

    @staticmethod
    def _popen(cmd: list[str]) -> None:
        try:
            subprocess.Popen(cmd)
        except FileNotFoundError:
            print(f"Can't run {cmd[0]}: not found")


@dataclass
class RemoteSessionAction(Action):
    """Opens a terminal/remote-desktop session, via remmina if it's installed."""
    uri: str = ""

    @classmethod
    def from_service(cls, service: "Service") -> "RemoteSessionAction":
        uri = f"{SESSION_SCHEMES[service.kind]}://{service.ip}:{service.port}"
        return cls(label=display_name(service.kind), uri=uri)

    async def run(self, scanner: "NetworkScanner") -> None:
        cmd = ["remmina", "-c", self.uri] if HAS_REMMINA else ["xdg-open", self.uri]
        self._popen(cmd)


@dataclass
class WebAdminAction(Action):
    """Opens a service's web admin page in the default browser."""
    uri: str = ""

    @classmethod
    def from_service(cls, service: "Service", path: str = "/", scheme: str = "http",
                      port: int | None = None, label: str | None = None) -> "WebAdminAction":
        # port: override for admin UIs that live on a different port than the one the
        # service was detected on (e.g. Sunshine's config UI vs. its GameStream port).
        # label: override for the default "{protocol name} admin" - a bare
        # protocol name (e.g. "Printing (IPP)") names *what this is*, not *what
        # clicking it does*; "X admin" says both. Some kinds read better with a
        # name other than their own protocol name here (ipp/cups both say
        # "Printer admin", not "Printing (IPP) admin"/"Printing (CUPS) admin" - the
        # protocol is an implementation detail the user doesn't need to see here).
        return cls(label=label or f"{display_name(service.kind)} admin",
                    uri=f"{scheme}://{service.ip}:{port or service.port}{path}")

    async def run(self, scanner: "NetworkScanner") -> None:
        self._popen(["xdg-open", self.uri])


@dataclass
class ShareAction(Action):
    """Opens one smb share in the system file manager."""
    uri: str = ""

    @classmethod
    def from_resource(cls, service: "Service", share: str) -> "ShareAction":
        return cls(label=share, uri=f"smb://{service.ip}/{share}")

    async def run(self, scanner: "NetworkScanner") -> None:
        self._popen(["xdg-open", self.uri])


@dataclass
class SmbPrinterAction(Action):
    """A basic placeholder for an SMB-shared printer resource. Unlike a file share,
    there's no single standard "open" action for a network printer - most desktops
    resolve one through their own Add Printer/CUPS dialog, not a URI a browser or
    file manager can act on directly. This reuses the same smb:// address a file
    share would use, since some file managers can still browse/resolve it; treat it
    as a starting point to build on, not a finished "connect me" flow."""
    uri: str = ""

    @classmethod
    def from_resource(cls, service: "Service", printer: str) -> "SmbPrinterAction":
        return cls(label=printer, uri=f"smb://{service.ip}/{printer}")

    async def run(self, scanner: "NetworkScanner") -> None:
        self._popen(["xdg-open", self.uri])


@dataclass
class IncusConsoleAction(Action):
    """Opens the incus web UI for one instance."""
    uri: str = ""

    @classmethod
    def from_resource(cls, service: "Service", instance: dict) -> "IncusConsoleAction":
        # incus's web UI has no stable per-instance deep link across versions, so this
        # just opens the UI root - the label at least tells you what to look for.
        uri = f"https://{service.ip}:{service.port}/ui/"
        return cls(label=f"{instance['name']} ({instance['status']})", uri=uri)

    async def run(self, scanner: "NetworkScanner") -> None:
        self._popen(["xdg-open", self.uri])


@dataclass
class SftpBrowseAction(Action):
    """Opens a path on an ssh host in the system file manager, over sftp:// via GVfs."""
    label: str = "browse"
    fields: tuple[str, ...] = ("user", "path")
    ip: str = ""
    port: int = 22

    @classmethod
    def from_service(cls, service: "Service") -> "SftpBrowseAction":
        return cls(ip=service.ip, port=service.port)

    async def run(self, scanner: "NetworkScanner", user: str = "", path: str = "") -> None:
        user = user.strip()
        path = path.strip()
        if path and not path.startswith("/"):
            path = f"/{path}"
        auth = f"{user}@" if user else ""
        port_part = f":{self.port}" if self.port != 22 else ""
        self._popen(["xdg-open", f"sftp://{auth}{self.ip}{port_part}{path}"])


@dataclass
class CredentialAction(Action):
    """Not a launch - submitting it re-queries the owning service with credentials,
    via the scanner passed into run() rather than a module-level global."""
    label: str = "sign in"
    fields: tuple[str, ...] = ("user", "password")
    service: "Service | None" = None
    failed: bool = False

    @classmethod
    def from_service(cls, service: "Service", failed: bool = False) -> "CredentialAction":
        return cls(service=service, failed=failed)

    async def run(self, scanner: "NetworkScanner", user: str = "", password: str = "") -> None:
        await scanner.request_items(self.service, user=user.strip(), password=password)
