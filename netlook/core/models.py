"""Device/Service data models - no dependency on any UI toolkit, and no dependency
on scanner.py at all (not even in type hints - see NetworkScanner.ensure_fetched,
which is what now decides whether to trigger a service's fetch, and Fetchable
below, which only describes state for that decision, never the scanner itself).
NetworkScanner (scanner.py) is what mutates these as discovery/probing happens; a
presentation layer only ever reads from them and calls resources()/enrich_device()
indirectly through it.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

from .actions import Action, LaunchAction, display_name


class ResourceCategory(str, Enum):
    """A tab in the device detail view. The thing being categorized is a *resource*
    (one specific actionable thing a service offers - a terminal launch, an sftp
    browser, a file share, ...), not the service itself: one Service can produce
    several resources, each independently belonging to whichever tab fits it (see
    Resource below, and Service.resources). Definition order here is the UI tab
    order."""
    PRINTERS = "Printers"
    SCREEN_SHARE = "Screen Share"
    TERMINAL = "Terminal"
    FILE_SHARES = "File Shares"
    VIRTUAL_MACHINES = "Virtual Machines"
    SYSTEM = "System"
    OTHER = "Other"


class FetchState(str, Enum):
    """Where a Fetchable service's own async fetch() currently stands - the
    read-only state NetworkScanner.ensure_fetched (scanner.py) inspects to decide
    whether to trigger fetch(), and the view layer inspects to decide whether to
    render a login prompt instead of resources (see ui/base.py's LoginPromptView).
    Deriving this from a service's own fields (loading, shares, auth_required, ...)
    rather than tracking it as a separate field keeps a single source of truth -
    there's no way for e.g. `loading=True` and `fetch_state=LOADED` to disagree."""
    NOT_FETCHED = "not_fetched"
    LOADING = "loading"
    LOADED = "loaded"
    AUTH_REQUIRED = "auth_required"


class Fetchable(ABC):
    """Mixed in by the handful of Service subclasses that fetch deeper data on
    first expand (Samba, Incus, Cups - see services.py). Exposes read-only state
    describing whether that data has been fetched yet; the decision of whether to
    actually trigger a fetch lives on NetworkScanner (see ensure_fetched in
    scanner.py), not here and not in the view layer, so the network tree stays
    self-sufficient rather than depending on a UI layer to interpret it."""

    @property
    @abstractmethod
    def fetch_state(self) -> FetchState: ...

    def fetch_fields(self) -> tuple[str, ...]:
        """Parameter names fetch() needs to proceed, given the current fetch_state -
        empty unless AUTH_REQUIRED (only Samba ever returns non-empty, and only
        then). Read by the view layer to render a login prompt's form fields."""
        return ()

    @abstractmethod
    async def fetch(self, **kwargs) -> None: ...


@dataclass
class Resource:
    """One thing a Service currently offers, tagged with the tab it belongs under.
    Yielded by Service.resources - the caller groups by .category rather than
    asking the service to filter itself, so a multi-resource service (ssh: a
    terminal launch tagged TERMINAL, an sftp browser tagged FILE_SHARES - one
    Service instance, and the credentials it holds, backing two distinct
    resources) is computed once and its resources sorted afterward, instead of
    being asked once per category it might span.

    immediate: whether this resource belongs in the collapsed row's always-visible
    Overview, as opposed to only appearing once a device row is expanded. True for
    most resources (a launch link that's already known costs nothing to show
    early); False for the handful that are either compute-once-per-instance
    clutter unsuited to a compact row (Incus's per-instance consoles, Cups's
    per-queue links), or only make sense once a service's own deeper data has been
    fetched (Samba's shares/printers, Ssh's sftp browser) - the same distinction
    `expanded` used to make by gating what Service.get_resources yielded at all,
    now made explicit as data instead of folded into when a resource is computed."""
    category: ResourceCategory
    action: Action
    immediate: bool = True


# service kind -> the category tab(s) its resources *might* appear under. A kind not
# listed here defaults to {OTHER} (see Service.categories). This has to stay a
# static, hand-authored mapping, not something derived by actually calling
# resources(): the UI needs to know whether to build a tab at all *before*
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
# Samba.resources.
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
SESSION_SCHEMES = {"ssh": "ssh", "rdp": "rdp", "vnc": "vnc"}


@dataclass
class WebAdminConfig:
    scheme: str
    path: str
    port: int | None = None  # None: use the port the service was detected on


WEB_ADMIN = {
    "home-assistant": WebAdminConfig("http", "/"),
    "moonlight": WebAdminConfig("https", "/", 47990),  # Sunshine's config UI, separate from its GameStream port
    # "cups" isn't here - it gets its own Service subclass, in services.py, for per-queue actions
}


def remote_session_action(service: Service) -> LaunchAction:
    """A terminal/remote-desktop launch link for an rdp/vnc/ssh-kind service. Lives
    here rather than on one specific Service subclass since it's shared across the
    base Service class below (rdp, vnc) and Ssh (services.py) identically - picking
    either one to "own" it would be arbitrary."""
    uri = f"{SESSION_SCHEMES[service.kind]}://{service.ip}:{service.port}"
    return LaunchAction(label=display_name(service.kind), uri=uri, opener="remmina")


def web_admin_action(service: Service, path: str = "/", scheme: str = "http",
                      port: int | None = None, label: str | None = None) -> LaunchAction:
    """A web admin page link. Lives here rather than on one specific Service
    subclass since it's shared across Home Assistant, Moonlight, Incus's
    always-visible link, Cups, and Ipp (services.py) identically.

    port: override for admin UIs that live on a different port than the one the
    service was detected on (e.g. Sunshine's config UI vs. its GameStream port).
    label: override for the default "{protocol name} admin" - a bare protocol name
    (e.g. "Printing (IPP)") names *what this is*, not *what clicking it does*; "X
    admin" says both. Some kinds read better with a name other than their own
    protocol name here (ipp/cups both say "Printer admin", not "Printing (IPP)
    admin"/"Printing (CUPS) admin" - the protocol is an implementation detail the
    user doesn't need to see here)."""
    return LaunchAction(label=label or f"{display_name(service.kind)} admin",
                         uri=f"{scheme}://{service.ip}:{port or service.port}{path}")


@dataclass
class Service:
    """A detected service on a device.

    resources() yields what can be done with it right now, purely from already-
    known state - no network I/O, no side effects. Each is tagged with the
    category it belongs under and whether it's `immediate` (belongs in the
    collapsed row's Overview) or not (only shown once a device row is expanded -
    see Resource.immediate). A Fetchable service (Samba, Incus, Cups - see
    services.py) whose data hasn't been fetched yet simply has fewer resources to
    yield until it has; triggering that fetch is NetworkScanner's job
    (ensure_fetched, in scanner.py), not this method's - resources() itself never
    needs a scanner reference at all. The default here covers any kind with a
    known launch scheme or web admin page, tagged with that kind's one static
    category (self.categories); kinds offering more than one distinct resource
    (smb, incus, ssh, cups, ...) register their own subclass instead (see
    services.py).
    """

    kind: str
    ip: str
    port: int
    properties: dict[bytes, bytes | None] = field(default_factory=dict)  # raw mDNS txt records
    discovered_name: str | None = None  # mDNS instance name, e.g. "MyNAS" - None for probed services
    expandable: ClassVar[bool] = False
    loading: bool = False

    def resources(self) -> Iterator[Resource]:
        """A kind handled here (rdp, vnc, moonlight, home-assistant, ...) has
        exactly one resource and no deeper structure to reveal (unlike
        smb/incus/cups, which register their own subclass specifically because
        they *do*) - so it's always immediate (the default), with nothing hidden
        behind expansion. next(iter(...)) is safe here because every kind
        reaching this default handler is single-category (see
        SERVICE_CATEGORIES) - a kind needing to tag different resources with
        different categories needs its own subclass instead."""
        if self.kind in LAUNCH_KINDS:
            yield Resource(next(iter(self.categories)), remote_session_action(self))
        elif self.kind in WEB_ADMIN:
            config = WEB_ADMIN[self.kind]
            yield Resource(next(iter(self.categories)),
                            web_admin_action(self, path=config.path, scheme=config.scheme, port=config.port))

    @property
    def status_text(self) -> str | None:
        return "loading..." if self.loading else None

    def txt(self, key: str) -> str | None:
        """Decoded value of one raw mDNS TXT record, or None if the key is absent or
        has no value. A point-lookup convenience over the raw properties dict, which
        stays bytes-keyed - the Properties tab's full dump (ui/base.py) iterates every
        key directly instead, since it has to show unknown keys too, not just the
        fixed ones a Service cares about."""
        value = self.properties.get(key.encode())
        return value.decode(errors="replace") if value is not None else None

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
        all (see SERVICE_CATEGORIES); resources() is the source of truth for what
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

    def _first_name(self, has_source, *, suffix_local: bool = False) -> str | None:
        """First hostname-shaped name in `names` (insertion order) whose sources
        satisfy `has_source`, or None - the shared tiered-lookup smb_host/ssh_host
        both build on. Only ever returns something _looks_like_hostname accepts: a
        reported name (an mDNS instance name, a WSD friendly name, ...) is a
        human-chosen display label, not necessarily a real NetBIOS/DNS hostname -
        "Stuart's NAS" is a perfectly good thing to show in the Names tab but an
        invalid smb://sftp:// uri authority (GVfs/libsmbclient rejects the space
        and apostrophe outright, as "invalid argument", before ever getting to
        actually resolving anything). A name that fails the check is skipped, not
        encoded - percent-encoding would make the uri syntactically valid but the
        encoded string still wouldn't be the device's real resolvable name, so
        connecting would just fail a different way (host not found) instead.

        suffix_local appends ".local" to a bare (undotted) name before returning
        it: an mDNS name only exists under that pseudo-TLD, and glibc's nss-mdns
        only ever intercepts a lookup actually suffixed with ".local" (its default
        nsswitch.conf wiring, mdns4_minimal, ignores a bare, undotted name) -
        confirmed against a real device where the bare mDNS instance name
        ("werner") failed to mount ("invalid argument" from a different cause than
        the unusable-display-name one above: GVfs fell through to NetBIOS/WINS
        resolution, which this network doesn't answer for it) while the same name
        suffixed with ".local" mounted fine. A non-mDNS name (WSD, ssh-known-hosts,
        etc-hosts) never gets this suffix - it's already whatever directly-usable
        form its own source reported (a real NetBIOS name for WSD; already
        resolvable as literally written for ssh-known-hosts/etc-hosts, being
        exactly what's already in those files)."""
        for name, sources in self.names.items():
            if has_source(sources) and _looks_like_hostname(name):
                return name if not suffix_local or "." in name else f"{name}.local"
        return None

    def smb_host(self) -> str:
        """The address to put in an smb:// uri for this device: any mDNS-reported
        name first (a service's own instance name, or _device-info's promoted one -
        the most likely to be both a real hostname and already how the rest of this
        device's UI refers to it), else a WSD (wsdd) name, else this device's IPv6
        address, else (always known) its IPv4 address. Recomputed from current
        `names` on every call rather than cached at discovery time, since a better
        name can arrive well after the smb service itself was first seen (WSD polls
        on its own interval - see discovery.WsdDiscovery - independently of mDNS).

        `_NON_MDNS_NAME_SOURCES` are the only source strings never wired to a
        Service.kind (see discovery.WsdDiscovery.SOURCE/SshKnownHostsDiscovery.
        SOURCE/EtcHostsDiscovery.SOURCE) - anything else recorded in `names` is an
        mDNS-derived name."""
        return (
            self._first_name(lambda sources: bool(sources - _NON_MDNS_NAME_SOURCES), suffix_local=True)
            or self._first_name(lambda sources: _WSD_NAME_SOURCE in sources)
            or self.ipv6 or self.ip
        )

    def ssh_host(self) -> str:
        """The address to put in an sftp:// uri for this device: a name from
        ~/.ssh/known_hosts first - not just any name, *specifically* whatever's
        already in known_hosts, so connecting here matches the exact host ssh
        itself already trusts and won't prompt about a host-key mismatch for what
        is, to ssh, an unrelated name/IP for the same server - else a name from
        /etc/hosts (likewise already a directly-usable, admin-maintained alias),
        else any mDNS-reported name (see smb_host, including the same ".local"
        handling - _first_name's suffix_local), else this device's IPv6 address,
        else (always known) its IPv4 address."""
        return (
            self._first_name(lambda sources: _SSH_KNOWN_HOSTS_SOURCE in sources)
            or self._first_name(lambda sources: _ETC_HOSTS_SOURCE in sources)
            or self._first_name(lambda sources: bool(sources - _NON_MDNS_NAME_SOURCES), suffix_local=True)
            or self.ipv6 or self.ip
        )


# Duplicated (not imported) from discovery.py's own SOURCE constants: models.py is
# deliberately dependency-free of discovery.py (see this module's docstring), and
# these three short string literals are a lighter coupling than pulling discovery's
# zeroconf/httpx/wsdiscovery imports in just to read them.
_WSD_NAME_SOURCE = "WSD"
_SSH_KNOWN_HOSTS_SOURCE = "ssh-known-hosts"
_ETC_HOSTS_SOURCE = "etc-hosts"
_NON_MDNS_NAME_SOURCES = {_WSD_NAME_SOURCE, _SSH_KNOWN_HOSTS_SOURCE, _ETC_HOSTS_SOURCE}

# RFC 952/1123-shaped: letters/digits/hyphens in each dot-separated label, no label
# starting or ending with a hyphen. Deliberately stricter than "no spaces" - also
# rejects apostrophes, parens, commas, and anything else a human-facing display name
# (as opposed to an actual hostname) might contain, all of which are equally invalid
# as an smb:// uri's authority component. See Device.smb_host.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
                           r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")


def _looks_like_hostname(name: str) -> bool:
    return bool(_HOSTNAME_RE.match(name))
