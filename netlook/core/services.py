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
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

import httpx

from .actions import (
    CredentialAction,
    IncusConsoleAction,
    RemoteSessionAction,
    ShareAction,
    SftpBrowseAction,
    SmbPrinterAction,
    WebAdminAction,
)
from .models import Device, Resource, ResourceCategory, Service, register
from .scanner import incus_get

if TYPE_CHECKING:
    from .scanner import NetworkScanner

logger = logging.getLogger(__name__)

HAS_SMBCLIENT = shutil.which("smbclient") is not None


@dataclass
class SmbShare:
    name: str
    comment: str = ""


async def list_smb_shares(ip: str, username: str | None = None,
                           password: str | None = None) -> tuple[list[SmbShare], list[SmbShare]] | None:
    """Returns (disk_shares, printer_shares) - either may genuinely be empty - or
    None if auth is required/failed."""
    if not HAS_SMBCLIENT:
        logger.warning("smbclient not found; can't list shares")
        return [], []

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


@register("smb")
@dataclass
class Samba(Service):
    expandable: ClassVar[bool] = True
    shares: list[SmbShare | str] | None = None
    printers: list[SmbShare | str] | None = None
    auth_required: bool = False
    tried_auth: bool = False  # True once a *credentialed* attempt has failed

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
        if self.shares is not None and not self.shares and not self.printers and not self.auth_required:
            return "no shares found"
        return None

    async def fetch(self, user: str = "", password: str = "") -> None:
        result = await list_smb_shares(self.ip, user or None, password)
        self.loading = False
        self.auth_required = result is None
        self.tried_auth = bool(user) and result is None
        self.shares, self.printers = result if result is not None else (None, None)

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        if not expanded or self.loading:
            return
        # auth_required must be checked before "shares is None": a failed fetch also
        # leaves shares as None, and re-triggering an anonymous fetch would loop
        # forever.
        if self.auth_required:
            yield Resource(ResourceCategory.FILE_SHARES, CredentialAction.from_service(self, failed=self.tried_auth))
            return
        if self.shares is None:
            await scanner.request_items(self)
            return
        # Both share types come from the same fetch and render together - see
        # SERVICE_CATEGORIES's comment on why smb doesn't get its own Printers tab.
        for share in self.shares:
            yield Resource(ResourceCategory.FILE_SHARES, ShareAction.from_resource(self, share))
        for printer in self.printers or []:
            yield Resource(ResourceCategory.FILE_SHARES, SmbPrinterAction.from_resource(self, printer))


@dataclass
class IncusInstance:
    name: str
    status: str


@register("incus")
@dataclass
class Incus(Service):
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

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        # The general web-admin link is yielded regardless of expanded, not just
        # collapsed: without it, a device with zero instances (or not yet fetched,
        # or inaccessible) would leave the Virtual Machines tab with a status_text
        # but nothing clickable at all - a dead end for a service that plainly has
        # a working link available, same principle as the base Service class and
        # ipp (see their get_resources). Per-instance console links, once fetched,
        # supplement this rather than replacing it.
        yield Resource(ResourceCategory.VIRTUAL_MACHINES,
                        WebAdminAction.from_service(self, path="/ui/", scheme="https"))
        if not expanded or self.loading:
            return
        if self.instances is None:
            await scanner.request_items(self)
            return
        for inst in self.instances:
            yield Resource(ResourceCategory.VIRTUAL_MACHINES, IncusConsoleAction.from_resource(self, inst))


@register("ssh")
@dataclass
class Ssh(Service):
    """ssh itself needs no fetch - the terminal launch is always available; expanding
    reveals an sftp path/user form for jumping into a file manager instead. Spans two
    categories, same idea as Samba spanning FILE_SHARES + PRINTERS: one ssh service
    (and the credentials it holds) backs two distinct resources - a terminal launch
    (TERMINAL) and an sftp file browser (FILE_SHARES) - each belonging in its own
    tab, not both crammed under "Terminal" just because one service produces them."""
    expandable: ClassVar[bool] = True

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        if not expanded:
            yield Resource(ResourceCategory.TERMINAL, RemoteSessionAction.from_service(self))
            return
        yield Resource(ResourceCategory.TERMINAL, RemoteSessionAction.from_service(self))
        yield Resource(ResourceCategory.FILE_SHARES, SftpBrowseAction.from_service(self))


class SilentService(Service):
    """A machine-to-machine protocol with no user-facing action - nothing here is
    ever clickable, so get_resources() always yields nothing."""

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        for _ in ():
            yield


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

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        # Ignores `expanded`: ipp has exactly one resource and no deeper structure
        # (unlike smb/incus/cups), so its Printers tab shows the same admin link
        # Overview does, rather than a dead, unclickable fallback label.
        admin_url = self.txt("adminurl")
        if admin_url:
            action = WebAdminAction(label="Printer admin", uri=admin_url)
        else:
            action = WebAdminAction.from_service(self, path="/", scheme="http", port=80, label="Printer admin")
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
class Cups(Service):
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

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        # The general web-admin link is yielded regardless of expanded, not just
        # collapsed - see Incus.get_resources for why: without it, a server with
        # zero queues (or not yet fetched) leaves the Printers tab with a
        # status_text but nothing clickable at all. Per-queue links, once fetched,
        # supplement this rather than replacing it.
        action = WebAdminAction.from_service(self, path="/", scheme="http", label="Printer admin")
        yield Resource(ResourceCategory.PRINTERS, action)
        if not expanded or self.loading:
            return
        if self.queues is None:
            await scanner.request_items(self)
            return
        for queue in self.queues:
            action = WebAdminAction(label=queue, uri=f"http://{self.ip}:{self.port}/printers/{queue}")
            yield Resource(ResourceCategory.PRINTERS, action)


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
