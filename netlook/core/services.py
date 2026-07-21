"""All concrete protocol Service subclasses. Each one registers itself against
SERVICE_REGISTRY (models.py) via the @register decorator - importing this module is
what populates the registry (see core/__init__.py).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import quote

import httpx

from .actions import LaunchAction, SftpBrowseAction
from .models import (
    Device,
    Fetchable,
    FetchState,
    Resource,
    ResourceCategory,
    Service,
    register,
    remote_session_action,
    web_admin_action,
)
from .scanner import incus_get

logger = logging.getLogger(__name__)

HAS_SMBCLIENT = shutil.which("smbclient") is not None


class SmbClientMissing(RuntimeError):
    """Raised by list_smb_shares when the smbclient binary itself isn't installed -
    deliberately distinct from both a genuinely empty listing ([], []) and an auth
    failure (None), neither of which this is: we never even got to ask the server.
    Conflating this with an empty listing used to make Samba.fetch report "no
    shares found" for every device, forever, on a machine missing the package -
    indistinguishable from a device that really has none."""


@dataclass
class SmbShare:
    name: str
    comment: str = ""


async def list_smb_shares(ip: str, username: str | None = None,
                           password: str | None = None) -> tuple[list[SmbShare], list[SmbShare]] | None:
    """Returns (disk_shares, printer_shares) - either may genuinely be empty - or
    None if auth is required/failed. Raises SmbClientMissing if the smbclient
    binary itself isn't installed."""
    if not HAS_SMBCLIENT:
        logger.warning("smbclient not found; can't list shares")
        raise SmbClientMissing

    cmd = ["smbclient", "-L", f"//{ip}", "-g"]
    env = None
    if username:
        cmd += ["-U", username]
        env = {**os.environ, "PASSWD": password or ""}  # avoid putting the password in argv
    else:
        cmd += ["-N"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL, env=env,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            logger.warning("smbclient timed out listing shares for %s", ip)
            proc.kill()
            await proc.wait()
            return None
    except OSError:
        logger.warning("Failed to invoke smbclient for %s", ip, exc_info=True)
        return None

    # grepable output: "Disk|ShareName|Comment" / "Printer|PrinterName|Comment"
    lines = stdout.decode(errors="replace").splitlines()
    shares = [SmbShare(parts[1], parts[2]) for line in lines
              if (parts := line.split("|"))[0] == "Disk"]
    printers = [SmbShare(parts[1], parts[2]) for line in lines
                if (parts := line.split("|"))[0] == "Printer"]
    if shares or printers or proc.returncode == 0:
        return shares, printers
    return None  # nonzero exit with nothing listed: treat as an auth failure


def _smb_authority(ip: str, username: str | None) -> str:
    """`user@host`, or just `host` if this fetch was anonymous. Only the username is
    embedded - never the password: it would otherwise sit in plain sight in argv
    (visible to any local user via `ps`) for the lifetime of the xdg-open process.
    Carrying the username at least means the file manager's own auth prompt only
    needs a password, not both, and most (GVfs-based) prompts offer to remember it
    via the keyring after that."""
    auth = f"{quote(username)}@" if username else ""
    return f"{auth}{ip}"


@register("smb")
@dataclass
class Samba(Service, Fetchable):
    expandable: ClassVar[bool] = True
    shares: list[SmbShare | str] | None = None
    printers: list[SmbShare | str] | None = None
    auth_required: bool = False
    tried_auth: bool = False  # True once a *credentialed* attempt has failed
    smbclient_missing: bool = False  # True once fetch() has found no smbclient binary
    # The username behind the current shares/printers listing, so links built from
    # it (see resources()) can carry it too - None for an anonymous listing.
    username: str | None = None
    # Set once by enrich_device, so _share_action/_printer_action can build their
    # smb:// uri from Device.smb_host() (a wsdd/mDNS name, preferred over a bare ip
    # - see that method) instead of always using self.ip. compare=False/repr=False:
    # this is a live back-reference, not this service's own data - comparing it
    # would recurse right back into this very Samba instance via Device.services,
    # and dataclass __eq__/__repr__ have no cycle protection.
    _device: "Device | None" = field(default=None, compare=False, repr=False)

    def __setattr__(self, name: str, value) -> None:
        # Lets `shares`/`printers` be assigned as bare share names (a plain string
        # has no comment to carry) as well as SmbShare - construction, fetch(), and
        # any later reassignment (tests, callers) all go through this, so there's
        # one coercion point instead of every call site remembering to wrap names.
        if name in ("shares", "printers") and value is not None:
            value = [v if isinstance(v, SmbShare) else SmbShare(v) for v in value]
        super().__setattr__(name, value)

    @property
    def status_text(self) -> str | None:
        if self.loading:
            return "loading..."
        if self.smbclient_missing:
            return "smbclient not installed"
        if self.shares is not None and not self.shares and not self.printers and not self.auth_required:
            return "no shares found"
        return None

    @property
    def fetch_state(self) -> FetchState:
        # auth_required must be checked before "shares is not None": a failed
        # fetch also leaves shares as None, so checking "not fetched yet" first
        # would misreport an auth failure as never having been attempted at all.
        if self.loading:
            return FetchState.LOADING
        if self.auth_required:
            return FetchState.AUTH_REQUIRED
        if self.shares is not None:
            return FetchState.LOADED
        return FetchState.NOT_FETCHED

    def fetch_fields(self) -> tuple[str, ...]:
        return ("user", "password") if self.fetch_state == FetchState.AUTH_REQUIRED else ()

    async def fetch(self, user: str = "", password: str = "") -> None:
        self.loading = False
        try:
            result = await list_smb_shares(self.ip, user or None, password)
        except SmbClientMissing:
            self.smbclient_missing = True
            self.auth_required = False
            self.tried_auth = False
            self.shares, self.printers = [], []
            self.username = None
            return
        self.auth_required = result is None
        self.tried_auth = bool(user) and result is None
        self.shares, self.printers = result if result is not None else (None, None)
        self.username = user or None if result is not None else None

    def enrich_device(self, device: "Device") -> None:
        super().enrich_device(device)
        self._device = device

    def _host(self) -> str:
        """Device.smb_host()'s wsdd/mDNS-preferred name, when this service has
        actually been attached to a device (see enrich_device) - a Samba built
        directly, without going through Device.add_service (only ever done in
        tests), falls back to its own bare ip instead."""
        return self._device.smb_host() if self._device else self.ip

    def _share_action(self, share: SmbShare) -> LaunchAction:
        return LaunchAction(label=share.name, uri=f"smb://{_smb_authority(self._host(), self.username)}/{share.name}")

    def _printer_action(self, printer: SmbShare) -> LaunchAction:
        """A basic placeholder for an SMB-shared printer resource. Unlike a file
        share, there's no single standard "open" action for a network printer -
        most desktops resolve one through their own Add Printer/CUPS dialog, not a
        uri a browser or file manager can act on directly. This reuses the same
        smb:// address a file share would use, since some file managers can still
        browse/resolve it; treat it as a starting point to build on, not a
        finished "connect me" flow."""
        return LaunchAction(label=printer.name,
                             uri=f"smb://{_smb_authority(self._host(), self.username)}/{printer.name}")

    def resources(self) -> Iterator[Resource]:
        # Nothing to yield until a fetch has actually landed - covers NOT_FETCHED,
        # LOADING, and AUTH_REQUIRED alike (all leave shares as None); triggering
        # that fetch, and surfacing a login prompt for AUTH_REQUIRED, are both the
        # caller's job now (see NetworkScanner.ensure_fetched and ui/base.py's
        # LoginPromptView), not this method's.
        if self.shares is None:
            return
        # Both share types come from the same fetch and render together - see
        # SERVICE_CATEGORIES's comment on why smb doesn't get its own Printers tab.
        for share in self.shares:
            yield Resource(ResourceCategory.FILE_SHARES, self._share_action(share), immediate=False)
        for printer in self.printers or []:
            yield Resource(ResourceCategory.FILE_SHARES, self._printer_action(printer), immediate=False)


@dataclass
class IncusInstance:
    name: str
    status: str


@register("incus")
@dataclass
class Incus(Service, Fetchable):
    expandable: ClassVar[bool] = True
    instances: list[IncusInstance] | None = None
    accessible: bool = True  # False: fetched, but the server didn't trust our client
    # incus/LXD's own error message for the failed request (e.g. "not authorized"
    # for an untrusted TLS client cert) - None unless accessible is False. The
    # Virtual Machines tab's status_text stays a brief "not accessible" (it has to
    # fit alongside action buttons in a compact tab); this is the real detail,
    # surfaced in Properties instead - see extra_properties.
    error: str | None = None

    @property
    def status_text(self) -> str | None:
        if self.loading:
            return "loading..."
        if self.instances is not None:
            if not self.accessible:
                return "not accessible"
            if not self.instances:
                return "no instances found"
        return None

    @property
    def fetch_state(self) -> FetchState:
        # "not accessible" (accessible=False) is still a completed fetch, not an
        # auth prompt - unlike Samba, Incus has no interactive retry-with-
        # credentials flow, so an inaccessible server just shows as LOADED with an
        # empty instance list and an explanatory error (see extra_properties).
        if self.loading:
            return FetchState.LOADING
        if self.instances is not None:
            return FetchState.LOADED
        return FetchState.NOT_FETCHED

    def extra_properties(self) -> list[tuple[str, str]]:
        return [("error", self.error)] if self.error else []

    async def fetch(self) -> None:
        payload = await incus_get(self.ip, self.port, "/1.0/instances?recursion=1")
        self.loading = False
        if not payload or payload.get("status_code") != 200 or not isinstance(payload.get("metadata"), list):
            self.instances = []
            self.accessible = False
            if not payload:
                self.error = "no response"  # connection failed, or the body wasn't valid JSON
            else:
                self.error = payload.get("error") or "unexpected response"
            return
        self.accessible = True
        self.error = None
        self.instances = [IncusInstance(i.get("name", "?"), i.get("status", "?")) for i in payload["metadata"]]

    def _console_action(self, instance: IncusInstance) -> LaunchAction:
        # incus's web UI has no stable per-instance deep link across versions, so
        # this just opens the UI root - the label at least tells you what to look
        # for.
        return LaunchAction(label=f"{instance.name} ({instance.status})", uri=f"https://{self.ip}:{self.port}/ui/")

    def resources(self) -> Iterator[Resource]:
        # The general web-admin link is always yielded, not just once fetched:
        # without it, a device with zero instances (or not yet fetched, or
        # inaccessible) would leave the Virtual Machines tab with a status_text but
        # nothing clickable at all - a dead end for a service that plainly has a
        # working link available, same principle as the base Service class and ipp
        # (see their resources()). Per-instance console links, once fetched,
        # supplement this rather than replacing it.
        yield Resource(ResourceCategory.VIRTUAL_MACHINES, web_admin_action(self, path="/ui/", scheme="https"))
        if self.instances is None:
            return
        for inst in self.instances:
            yield Resource(ResourceCategory.VIRTUAL_MACHINES, self._console_action(inst), immediate=False)


@register("ssh")
@dataclass
class Ssh(Service):
    """ssh itself needs no fetch - the terminal launch is always available; expanding
    the row reveals an sftp path/user form for jumping into a file manager instead
    (immediate=False, below - not gated on any fetch, just not worth cluttering the
    collapsed row with). Spans two categories, same idea as Samba spanning
    FILE_SHARES + PRINTERS: one ssh service (and the credentials it holds) backs
    two distinct resources - a terminal launch (TERMINAL) and an sftp file browser
    (FILE_SHARES) - each belonging in its own tab, not both crammed under
    "Terminal" just because one service produces them."""
    expandable: ClassVar[bool] = True
    # Set once by enrich_device, so _host can build the sftp:// browse link from
    # Device.ssh_host() (a known_hosts/etc-hosts/mDNS name, preferred over a bare
    # ip - see that method) instead of always using self.ip. compare=False/
    # repr=False for the same reason as Samba._device (see there): a live
    # back-reference, not this service's own data, whose equality would otherwise
    # recurse right back into this very Ssh instance via Device.services.
    _device: "Device | None" = field(default=None, compare=False, repr=False)

    def enrich_device(self, device: "Device") -> None:
        super().enrich_device(device)
        self._device = device

    def _host(self) -> str:
        """Device.ssh_host() when this service has actually been attached to a
        device (see enrich_device) - an Ssh built directly, without going through
        Device.add_service (only ever done in tests), falls back to its own bare ip
        instead."""
        return self._device.ssh_host() if self._device else self.ip

    def resources(self) -> Iterator[Resource]:
        yield Resource(ResourceCategory.TERMINAL, remote_session_action(self))
        sftp = SftpBrowseAction(ip=self._host(), port=self.port)
        yield Resource(ResourceCategory.FILE_SHARES, sftp, immediate=False)


class SilentService(Service):
    """A machine-to-machine protocol with no user-facing action - nothing here is
    ever clickable, so resources() always yields nothing."""

    def resources(self) -> Iterator[Resource]:
        yield from ()


@register("pdl-datastream")
@dataclass
class PdlStreamService(SilentService):
    """AppSocket/JetDirect raw printing (usually port 9100) - a protocol between a
    print spooler and the printer itself."""


@register("printer")
@dataclass
class LpdPrinterService(SilentService):
    """Legacy LPD/LPR network printing."""


@register("ipp", "ipps")
@dataclass
class Ipp(Service):
    """Modern IPP/IPPS printer sharing. Bonjour IPP advertisements often carry an
    "adminurl" txt record pointing straight at the printer's web status page - trust
    that when it's there, since it's more reliable than guessing a port; port 80 is
    the fallback, since that's where most printers' embedded web servers live."""

    def resources(self) -> Iterator[Resource]:
        # ipp has exactly one resource and no deeper structure (unlike
        # smb/incus/cups), so its Printers tab shows the same admin link Overview
        # does (immediate, the default), rather than a dead, unclickable fallback
        # label.
        admin_url = self.txt("adminurl")
        if admin_url:
            action = LaunchAction(label="Printer admin", uri=admin_url)
        else:
            action = web_admin_action(self, path="/", scheme="http", port=80, label="Printer admin")
        yield Resource(ResourceCategory.PRINTERS, action)

    def enrich_device(self, device: "Device") -> None:
        super().enrich_device(device)  # offers the mDNS instance name as an alias too
        # "ty" (type) is the human-readable model/description Bonjour printer shares
        # standardize (e.g. "HP LaserJet Pro M404dn"); "note" is whatever the admin
        # set (often a location, e.g. "2nd Floor") - both are useful supplementary
        # info, so they're offered as aliases rather than promoted over a name someone
        # deliberately gave the device.
        for key in ("ty", "note"):
            value = self.txt(key)
            if value:
                device.add_alias(self.kind, value)


_CUPS_QUEUE_RE = re.compile(rb'href="/printers/([^"/]+)"', re.IGNORECASE)


@register("cups")
@dataclass
class Cups(Service, Fetchable):
    """A CUPS server can host several physical printer queues; each queue is a
    resource, listed lazily (mirrors how Incus lists instances). CUPS has no clean
    machine-readable "list queues" endpoint short of the binary IPP protocol, so this
    scrapes queue names out of its HTML /printers/ page instead - best-effort (CUPS's
    markup isn't a stable contract the way incus's JSON API is), but turns "a print
    server" into "these specific queues," each one click away."""

    expandable: ClassVar[bool] = True
    queues: list[str] | None = None

    @property
    def status_text(self) -> str | None:
        if self.loading:
            return "loading..."
        if self.queues is not None and not self.queues:
            return "no queues found"
        return None

    @property
    def fetch_state(self) -> FetchState:
        if self.loading:
            return FetchState.LOADING
        if self.queues is not None:
            return FetchState.LOADED
        return FetchState.NOT_FETCHED

    async def fetch(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                response = await client.get(f"http://{self.ip}:{self.port}/printers/")
                body = response.content
        except (OSError, httpx.HTTPError):
            logger.warning("Failed to fetch CUPS printer queues from %s:%s", self.ip, self.port, exc_info=True)
            body = b""
        self.loading = False
        self.queues = sorted({m.decode(errors="replace") for m in _CUPS_QUEUE_RE.findall(body)})

    def resources(self) -> Iterator[Resource]:
        # The general web-admin link is always yielded, not just once fetched -
        # see Incus.resources() for why: without it, a server with zero queues (or
        # not yet fetched) leaves the Printers tab with a status_text but nothing
        # clickable at all. Per-queue links, once fetched, supplement this rather
        # than replacing it.
        action = web_admin_action(self, path="/", scheme="http", label="Printer admin")
        yield Resource(ResourceCategory.PRINTERS, action)
        if self.queues is None:
            return
        for queue in self.queues:
            action = LaunchAction(label=queue, uri=f"http://{self.ip}:{self.port}/printers/{queue}")
            yield Resource(ResourceCategory.PRINTERS, action, immediate=False)


@register("device-info")
@dataclass
class DeviceInfo(Service):
    """Carries no actions of its own - _device-info._tcp exists purely to advertise
    txt records about the device it's running on, so this is the metadata-enrichment
    service: it exists to update its parent Device rather than to be interacted with."""

    def enrich_device(self, device: "Device") -> None:
        # "model" (e.g. "MacBookPro18,3") is deliberately never used as a name or
        # alias here - it's hardware metadata, not something anyone would call the
        # device by. It's still visible verbatim in the Properties tab's raw txt
        # record dump, so nothing is lost by leaving it out of Names; a device with
        # no discovered_name at all just falls back to showing its IP as hostname
        # instead of a model code.
        if self.discovered_name:
            device.promote_name(self.kind, self.discovered_name)

        # not a standard _device-info._tcp key, but wired up for any future service
        # (registered here or elsewhere) that advertises one.
        icon = self.txt("icon")
        if icon:
            device.icon_path = icon
