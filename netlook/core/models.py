"""Device/Service data models - no dependency on any UI toolkit or on scanner.py at
runtime (only in type hints, guarded by TYPE_CHECKING). NetworkScanner (scanner.py)
is what mutates these as discovery/probing happens; a presentation layer only ever
reads from them and calls get_resources()/enrich_device() indirectly through it.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, ClassVar

from .actions import Action, RemoteSessionAction, WebAdminAction

if TYPE_CHECKING:
    from .scanner import NetworkScanner


class ResourceCategory(str, Enum):
    """A tab in the device detail view. The thing being categorized is a *resource*
    (one specific actionable thing a service offers - a terminal launch, an sftp
    browser, a file share, ...), not the service itself: one Service can produce
    several resources, each independently belonging to whichever tab fits it (see
    Resource below, and Service.get_resources). Definition order here is the UI tab
    order."""
    PRINTERS = "Printers"
    SCREEN_SHARE = "Screen Share"
    TERMINAL = "Terminal"
    FILE_SHARES = "File Shares"
    VIRTUAL_MACHINES = "Virtual Machines"
    SYSTEM = "System"
    OTHER = "Other"


@dataclass
class Resource:
    """One thing a Service currently offers, tagged with the tab it belongs under.
    Yielded by Service.get_resources - the caller groups by .category rather than
    asking the service to filter itself, so a multi-resource service (ssh: a
    terminal launch tagged TERMINAL, an sftp browser tagged FILE_SHARES - one
    Service instance, and the credentials it holds, backing two distinct
    resources) is computed once and its resources sorted afterward, instead of
    being asked once per category it might span."""
    category: ResourceCategory
    action: Action


# service kind -> the category tab(s) its resources *might* appear under. A kind not
# listed here defaults to {OTHER} (see Service.categories). This has to stay a
# static, hand-authored mapping, not something derived by actually calling
# get_resources(): the UI needs to know whether to build a tab at all *before*
# triggering any fetch (lazy loading - see build_device_row_view), so it can't
# afford to wait for real resources to find out which categories exist. Most kinds
# need only one category, but a kind can span several when it offers more than one
# distinct resource that belongs in a genuinely different tab: ssh offers both a
# terminal launch and an sftp file browser (TERMINAL + FILE_SHARES). smb is
# deliberately *not* multi-category even though it can host printer shares as well
# as file shares: unlike ssh's two resources, both of smb's come from the same
# single fetch and belong together - putting them in a dedicated Printers tab would
# mean a static, pre-fetch category membership (decided before we know whether any
# printer shares actually exist) creating a dead label for the common case of a
# purely file-sharing device. They render together in File Shares instead - see
# Samba.get_resources.
SERVICE_CATEGORIES: dict[str, set[ResourceCategory]] = {
    "ssh": {ResourceCategory.TERMINAL, ResourceCategory.FILE_SHARES},
    "rdp": {ResourceCategory.SCREEN_SHARE},
    "vnc": {ResourceCategory.SCREEN_SHARE},
    "moonlight": {ResourceCategory.SCREEN_SHARE},
    "smb": {ResourceCategory.FILE_SHARES},
    "cups": {ResourceCategory.PRINTERS},
    "ipp": {ResourceCategory.PRINTERS},
    "ipps": {ResourceCategory.PRINTERS},
    "printer": {ResourceCategory.PRINTERS},
    "pdl-datastream": {ResourceCategory.PRINTERS},
    "incus": {ResourceCategory.VIRTUAL_MACHINES},
    "home-assistant": {ResourceCategory.SYSTEM},
    "device-info": {ResourceCategory.SYSTEM},
}

# category -> a synthetic "group kind" (registered in actions.PROTOCOL_NAMES, not a
# real discovered Service.kind) used when that category's tab should combine every
# matching service into one CategoryEntry under one shared header, instead of the
# default one-entry-per-service. Printers is the first case: a single physical
# printer commonly advertises via several protocols at once (ipp + pdl-datastream +
# sometimes cups/LPD) - showing each as its own header/block is repetition, not
# information, since they're all the same printer. A category not listed here keeps
# the default per-service behavior - see build_device_row_view in ui/base.py, which
# is the only place this is read.
GROUPED_CATEGORIES: dict[ResourceCategory, str] = {
    ResourceCategory.PRINTERS: "printer-group",
}

LAUNCH_KINDS = {"rdp", "vnc"}  # "ssh" gets its own subclass, in services.py
# kind -> (scheme, path, port override or None to use the port the service was detected on)
WEB_ADMIN = {
    "home-assistant": ("http", "/", None),
    "moonlight": ("https", "/", 47990),  # Sunshine's config UI, separate from its GameStream port
    # "cups" isn't here - it gets its own Service subclass, in services.py, for per-queue actions
}


@dataclass
class Service:
    """A detected service on a device.

    get_resources(expanded, scanner) yields what can be done with it right now, each
    tagged with the category it belongs under: called with expanded=False for the
    row's always-visible resources, and expanded=True (only once the user opens the
    row's toggle) for anything that needs a network fetch or user input first.
    `scanner` is threaded through explicitly (not a global) so a service can kick
    off a background fetch via scanner.request_items(self, ...). The default here
    covers any kind with a known launch scheme or web admin page, tagged with that
    kind's one static category (self.categories); kinds offering more than one
    distinct resource (smb, incus, ssh, cups, ...) register their own subclass
    instead (see services.py).
    """

    kind: str
    ip: str
    port: int
    properties: dict[bytes, bytes | None] = field(default_factory=dict)  # raw mDNS txt records
    discovered_name: str | None = None  # mDNS instance name, e.g. "MyNAS" - None for probed services
    expandable: ClassVar[bool] = False
    loading: bool = False

    async def get_resources(self, expanded: bool, scanner: "NetworkScanner") -> AsyncIterator[Resource]:
        """Deliberately ignores `expanded`: a kind handled here (rdp, vnc,
        moonlight, home-assistant, ...) has exactly one resource and no deeper
        structure to reveal once expanded (unlike smb/incus/cups, which register
        their own subclass specifically because they *do*) - so its category tab
        shows the same resource Overview does, rather than nothing. A category tab
        with no clickable content when the service plainly has one available is a
        dead end, not a meaningful "nothing more to see here". next(iter(...)) is
        safe here because every kind reaching this default handler is
        single-category (see SERVICE_CATEGORIES) - a kind needing to tag different
        resources with different categories needs its own subclass instead."""
        if self.kind in LAUNCH_KINDS:
            yield Resource(next(iter(self.categories)), RemoteSessionAction.from_service(self))
        elif self.kind in WEB_ADMIN:
            scheme, path, port = WEB_ADMIN[self.kind]
            yield Resource(next(iter(self.categories)),
                            WebAdminAction.from_service(self, path=path, scheme=scheme, port=port))

    @property
    def status_text(self) -> str | None:
        return "loading..." if self.loading else None

    def extra_properties(self) -> list[tuple[str, str]]:
        """Extra (key, value) pairs to show in the Properties tab alongside this
        service's raw mDNS TXT records - runtime/fetched diagnostic detail that
        was never advertised over mDNS at all, so it has nowhere else to live.
        Empty by default; a service overrides this when it has something to
        explain beyond a brief category-tab status_text (e.g. Incus surfacing
        *why* it's "not accessible" - a real error message from the server,
        not just the fact that something's wrong)."""
        return []

    @property
    def categories(self) -> set[ResourceCategory]:
        """Which category tab(s) this service's resources might appear under - a
        cheap, static, pre-fetch answer used to decide whether to build a tab at
        all (see SERVICE_CATEGORIES); get_resources is the source of truth for what
        actually renders inside it."""
        return SERVICE_CATEGORIES.get(self.kind, {ResourceCategory.OTHER})

    def enrich_device(self, device: "Device") -> None:
        """Called once, right after this service is attached to `device`. Default:
        record this service's own mDNS instance name, sourced under this service's
        kind (e.g. "smb"). Metadata-rich services (DeviceInfo, ...) override this to
        promote a better name to primary instead, or to fill in other display
        metadata like icon_path."""
        if self.discovered_name:
            device.add_alias(self.kind, self.discovered_name)


SERVICE_REGISTRY: dict[str, type[Service]] = {}


def register(*kinds: str):
    """Class decorator mapping mDNS/probe service kinds to a Service subclass."""
    def deco(cls):
        for kind in kinds:
            SERVICE_REGISTRY[kind] = cls
        return cls
    return deco


def make_service(kind: str, ip: str, port: int, properties: dict | None = None,
                  discovered_name: str | None = None) -> Service:
    cls = SERVICE_REGISTRY.get(kind, Service)
    return cls(kind=kind, ip=ip, port=port, properties=properties or {}, discovered_name=discovered_name)


# mDNS service type name -> our canonical service kind, for the rare case where the
# Bonjour type name isn't what we key/label the service as - e.g. VNC/Screen Sharing
# advertises as "_rfb._tcp" (the underlying protocol name), not "_vnc._tcp".
KIND_ALIASES = {"rfb": "vnc"}


def kind_from_type(type_or_name: str) -> str:
    # "_ssh._tcp.local." -> "ssh"
    kind = type_or_name.split(".")[0].lstrip("_")
    return KIND_ALIASES.get(kind, kind)


@dataclass
class Device:
    hostname: str  # the primary/display name
    ip: str
    ipv6: str | None = None
    icon_path: str | None = None  # set by a service's enrich_device, e.g. DeviceInfo
    # every name any service has reported, name -> the set of source_service_names
    # (Service.kind, e.g. "smb", "device-info") that reported it - a name gets one
    # entry no matter how many sources agree on it, so aliases never show a duplicate
    names: dict[str, set[str]] = field(default_factory=dict)
    services: dict[str, Service] = field(default_factory=dict)
    # (interface name, mac address) pairs - only ever non-empty for this machine's
    # own Device entry (see scanner.py's _detect_local_physical_interfaces); every
    # other device has no way for us to learn its physical interfaces, so this
    # stays empty for them, which is exactly what the "Physical Devices" section in
    # the Properties tab uses to decide whether to show itself at all.
    physical_interfaces: list[tuple[str, str]] = field(default_factory=list)

    def add_service(self, type_or_name: str, port: int, properties: dict | None = None,
                     discovered_name: str | None = None, ip: str | None = None) -> None:
        # ip overrides self.ip for the rare case where a service was only reachable
        # at a different address than the device's own canonical one - this
        # machine's own probed services, specifically (see NetworkScanner._probe):
        # a service bound loopback-only (a common, deliberately secure default -
        # CUPS often ships this way) would never answer on the LAN address, so the
        # resulting action needs to point at wherever it actually answered, not
        # blindly at self.ip.
        kind = kind_from_type(type_or_name)
        if kind not in self.services:
            service = make_service(kind, ip or self.ip, port, properties, discovered_name)
            self.services[kind] = service
            service.enrich_device(self)

    def promote_name(self, source: str, name: str) -> None:
        """Record `name` (reported by `source`) and make it the primary hostname."""
        name = name.strip()
        if not name:
            return
        self.names.setdefault(name, set()).add(source)
        self.hostname = name

    def add_alias(self, source: str, name: str) -> None:
        """Record `name` (reported by `source`) as a known name for this device. Kept
        even if it duplicates the current hostname, so the primary name's own
        provenance is preserved too - `aliases` filters those back out for display."""
        name = name.strip()
        if name:
            self.names.setdefault(name, set()).add(source)

    @property
    def aliases(self) -> dict[str, set[str]]:
        """Known names other than the current primary hostname, name -> sources."""
        return {name: sources for name, sources in self.names.items() if name != self.hostname}
