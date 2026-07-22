"""Device/Service data models. No dependency on any UI toolkit or on scanner.py.

NetworkScanner (scanner.py) mutates these during discovery/probing. Fetchable
only describes fetch state; NetworkScanner.ensure_fetched decides whether to
fetch. The UI only reads these and calls resources()/enrich_device() via the
scanner.
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
    """A tab in the device detail view.

    Categorises resources (actionable things a service offers), not services -
    one service can yield several resources across different tabs. See Resource
    and Service.resources. Definition order here is the tab order."""
    PRINTERS = "Printers"
    SCREEN_SHARE = "Screen Share"
    TERMINAL = "Terminal"
    FILE_SHARES = "File Shares"
    VIRTUAL_MACHINES = "Virtual Machines"
    SYSTEM = "System"
    OTHER = "Other"


class FetchState(str, Enum):
    """State of a Fetchable service's fetch().

    Read by NetworkScanner.ensure_fetched to decide whether to fetch, and by
    the UI to decide whether to show a login prompt (see LoginPromptView).
    Derived from the service's own fields rather than stored separately, so
    it can't disagree with them."""
    NOT_FETCHED = "not_fetched"
    LOADING = "loading"
    LOADED = "loaded"
    AUTH_REQUIRED = "auth_required"


class Fetchable(ABC):
    """Mixed in by Service subclasses that fetch deeper data on first expand
    (Samba, Incus, Cups - see services.py).

    Exposes read-only fetch state only. NetworkScanner.ensure_fetched decides
    whether to actually fetch."""

    @property
    @abstractmethod
    def fetch_state(self) -> FetchState: ...

    def fetch_fields(self) -> tuple[str, ...]:
        """Parameter names fetch() needs, given the current fetch_state.

        Empty unless AUTH_REQUIRED (only Samba returns fields). Used to
        render the login prompt's form fields."""
        return ()

    @abstractmethod
    async def fetch(self, **kwargs) -> None: ...


@dataclass
class Resource:
    """One thing a Service currently offers, tagged with the tab it belongs under.

    Yielded by Service.resources; the caller groups by .category. A service
    with resources in several tabs (e.g. ssh: terminal + sftp) is computed
    once, not once per category.

    immediate: shown in the collapsed row's Overview, not just on expand.
    True for most resources. False for per-instance clutter (Incus consoles,
    Cups per-queue links) or resources that need a service's fetched data
    first (Samba shares, Ssh's sftp browser)."""
    category: ResourceCategory
    action: Action
    immediate: bool = True


# service kind -> the category tab(s) its resources might appear under. A kind
# not listed here defaults to {OTHER} (see Service.categories).
#
# Hand-authored rather than derived from resources(): the UI needs to know
# whether to build a tab before triggering any fetch (see
# build_device_row_view), so it can't wait for real resources.
#
# ssh spans two categories (terminal + sftp) because it offers two distinct
# resources. smb stays single-category even though it can host printers:
# both come from the same fetch and render together in File Shares (see
# Samba.resources), rather than a dedicated Printers tab that would sit empty
# whenever a device has no printer shares.
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

# category -> synthetic "group kind" (registered in actions.PROTOCOL_NAMES, not
# a real Service.kind), used when a tab should combine every matching service
# under one shared header instead of one entry per service.
#
# Printers is the only case: a printer often advertises via several protocols
# at once (ipp, pdl-datastream, sometimes cups/LPD), and showing each as its
# own block would just repeat the same printer. See build_device_row_view in
# ui/base.py, the only place this is read.
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
    """Terminal/remote-desktop launch link for an rdp/vnc/ssh service.

    Shared by Service (rdp, vnc) and Ssh (services.py), so it lives here
    rather than on either one."""
    uri = f"{SESSION_SCHEMES[service.kind]}://{service.ip}:{service.port}"
    return LaunchAction(label=display_name(service.kind), uri=uri, opener="remmina")


def web_admin_action(service: Service, path: str = "/", scheme: str = "http",
                      port: int | None = None, label: str | None = None) -> LaunchAction:
    """Web admin page link.

    Shared by Home Assistant, Moonlight, Incus, Cups and Ipp (services.py),
    so it lives here rather than on any one of them.

    port: override when the admin UI lives on a different port than the one
    the service was detected on (e.g. Sunshine's config UI vs its GameStream
    port).
    label: override for the default "{protocol name} admin". Some kinds read
    better with a shared name (ipp/cups both use "Printer admin" rather than
    naming the protocol)."""
    return LaunchAction(label=label or f"{display_name(service.kind)} admin",
                         uri=f"{scheme}://{service.ip}:{port or service.port}{path}")


@dataclass
class Service:
    """A detected service on a device.

    resources() yields what can be done with it right now, from already-known
    state only - no network I/O. Each is tagged with its category and whether
    it's `immediate` (Overview) or expand-only (see Resource.immediate). A
    Fetchable service with no data fetched yet just yields fewer resources;
    triggering the fetch is NetworkScanner's job (ensure_fetched), not this
    method's.

    The default here handles any kind with a launch scheme or web admin page.
    Kinds with more than one distinct resource (smb, incus, ssh, cups, ...)
    register their own subclass instead (services.py).
    """

    kind: str
    ip: str
    port: int
    properties: dict[bytes, bytes | None] = field(default_factory=dict)  # raw mDNS txt records
    discovered_name: str | None = None  # mDNS instance name, e.g. "MyNAS" - None for probed services
    expandable: ClassVar[bool] = False
    loading: bool = False

    def resources(self) -> Iterator[Resource]:
        """Kinds handled here (rdp, vnc, moonlight, home-assistant, ...) have
        exactly one resource, always immediate. next(iter(...)) is safe
        because every kind reaching this default is single-category (see
        SERVICE_CATEGORIES); a kind needing several categories needs its own
        subclass instead."""
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
        """Decoded value of one raw mDNS TXT record, or None if absent/empty.

        A convenience lookup over the bytes-keyed properties dict. The
        Properties tab dumps the dict directly instead, since it needs
        unknown keys too."""
        value = self.properties.get(key.encode())
        return value.decode(errors="replace") if value is not None else None

    def extra_properties(self) -> list[tuple[str, str]]:
        """Extra (key, value) pairs for the Properties tab, alongside the raw
        mDNS TXT records - runtime/fetched detail with nowhere else to live.

        Empty by default. Override when there's more to explain than
        status_text covers (e.g. Incus surfacing the actual "not accessible"
        error)."""
        return []

    @property
    def categories(self) -> set[ResourceCategory]:
        """Category tab(s) this service's resources might appear under.

        Cheap, static, pre-fetch (see SERVICE_CATEGORIES) - used to decide
        whether to build a tab at all. resources() decides what renders
        inside it."""
        return SERVICE_CATEGORIES.get(self.kind, {ResourceCategory.OTHER})

    def enrich_device(self, device: "Device") -> None:
        """Called once, right after this service is attached to `device`.

        Default: record this service's mDNS instance name under its kind
        (e.g. "smb"). Metadata-rich services (DeviceInfo, ...) override this
        to promote a better name to primary, or set other display metadata
        like icon_path."""
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
    # Every name any service has reported: name -> set of source kinds (e.g.
    # "smb", "device-info") that reported it. One entry per name, so aliases
    # never show a duplicate.
    names: dict[str, set[str]] = field(default_factory=dict)
    services: dict[str, Service] = field(default_factory=dict)
    # (interface name, mac address) pairs. Only ever set for this machine's own
    # Device entry (see scanner.py's _detect_local_physical_interfaces) - we
    # have no way to learn another device's interfaces. Empty elsewhere, which
    # is what the Properties tab's "Physical Devices" section checks to decide
    # whether to show itself.
    physical_interfaces: list[tuple[str, str]] = field(default_factory=list)
    # discovery.py engine SOURCE tags that found this device, one per engine
    # regardless of whether it contributed a name. Separate from `names`
    # because a queue_probe engine still "finds" a device with no hostname.
    # Drives the Properties tab's "Finders" section.
    found_by: set[str] = field(default_factory=set)
    # Reverse-DNS (PTR) name for `ip`, or None if none was found - populated
    # lazily by NetworkScanner.ensure_dns_resolved, never by build_device_row_view
    # itself. Drives the Properties tab's "DNS" section.
    dns_hostname: str | None = None
    # Whether a reverse-DNS lookup has been attempted yet, so
    # ensure_dns_resolved doesn't repeat one every time a row expands - the
    # same NOT_FETCHED-style gate Fetchable.fetch_state provides for services.
    dns_resolved: bool = False

    def add_service(self, type_or_name: str, port: int, properties: dict | None = None,
                     discovered_name: str | None = None, ip: str | None = None) -> None:
        # ip overrides self.ip when a service only answers at a different
        # address - this machine's own probed services (see
        # NetworkScanner._probe). A loopback-only service (CUPS often ships
        # this way) never answers on the LAN address, so the action needs to
        # point at wherever it actually answered.
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
        """Record `name` (reported by `source`) as a known name for this device.

        Kept even if it duplicates the hostname, to preserve provenance -
        `aliases` filters it back out for display."""
        name = name.strip()
        if name:
            self.names.setdefault(name, set()).add(source)

    @property
    def aliases(self) -> dict[str, set[str]]:
        """Known names other than the current primary hostname, name -> sources."""
        return {name: sources for name, sources in self.names.items() if name != self.hostname}

    def _first_name(self, has_source, *, suffix_local: bool = False) -> str | None:
        """First hostname-shaped name in `names` (insertion order) whose
        sources satisfy `has_source`, or None. Shared by smb_host/ssh_host.

        Only returns names _looks_like_hostname accepts. A reported display
        name like "Stuart's NAS" is fine for the Names tab but breaks as an
        smb:// URI authority (GVfs/libsmbclient reject the space and
        apostrophe). Names that fail the check are skipped, not encoded -
        percent-encoding would produce a valid URI but not the device's real
        resolvable name, so it would just fail to connect a different way.

        suffix_local appends ".local" to a bare name: an mDNS name only
        exists under that pseudo-TLD, and glibc's nss-mdns (mdns4_minimal)
        ignores a bare, undotted lookup. Confirmed against a real device: the
        bare mDNS name "werner" failed to mount, but "werner.local" worked.
        Non-mDNS names (WSD, ssh-known-hosts, etc-hosts) never get this
        suffix - they're already directly usable as reported."""
        for name, sources in self.names.items():
            if has_source(sources) and _looks_like_hostname(name):
                return name if not suffix_local or "." in name else f"{name}.local"
        return None

    def smb_host(self) -> str:
        """Address for this device's smb:// URI: an mDNS-reported name first,
        else a WSD name, else IPv6, else IPv4 (always known).

        Recomputed on every call, not cached, since a better name can arrive
        after the smb service is first seen (WSD polls independently of mDNS
        - see discovery.WsdDiscovery).

        `_NON_MDNS_NAME_SOURCES` are the only source strings not wired to a
        Service.kind (see discovery.WsdDiscovery.SOURCE etc.); anything else
        in `names` is mDNS-derived."""
        return (
            self._first_name(lambda sources: bool(sources - _NON_MDNS_NAME_SOURCES), suffix_local=True)
            or self._first_name(lambda sources: _WSD_NAME_SOURCE in sources)
            or self.ipv6 or self.ip
        )

    def ssh_host(self) -> str:
        """Address for this device's sftp:// URI: a ~/.ssh/known_hosts name
        first (so it matches what ssh already trusts, avoiding a host-key
        mismatch prompt), else /etc/hosts, else an mDNS name (see smb_host),
        else IPv6, else IPv4."""
        return (
            self._first_name(lambda sources: _SSH_KNOWN_HOSTS_SOURCE in sources)
            or self._first_name(lambda sources: _ETC_HOSTS_SOURCE in sources)
            or self._first_name(lambda sources: bool(sources - _NON_MDNS_NAME_SOURCES), suffix_local=True)
            or self.ipv6 or self.ip
        )


# Duplicated (not imported) from discovery.py's SOURCE constants: models.py
# stays dependency-free of discovery.py (see module docstring), and these
# string literals are lighter than pulling in discovery's zeroconf/httpx/
# wsdiscovery imports just to read them.
_WSD_NAME_SOURCE = "WSD"
_SSH_KNOWN_HOSTS_SOURCE = "ssh-known-hosts"
_ETC_HOSTS_SOURCE = "etc-hosts"
_ARP_CACHE_SOURCE = "arp-cache"
_NON_MDNS_NAME_SOURCES = {_WSD_NAME_SOURCE, _SSH_KNOWN_HOSTS_SOURCE, _ETC_HOSTS_SOURCE, _ARP_CACHE_SOURCE}

# RFC 952/1123-shaped: letters/digits/hyphens per label, no label starting or
# ending with a hyphen. Stricter than "no spaces" - also rejects apostrophes,
# parens, commas and anything else a display name might contain but an
# smb:// URI authority can't. See Device.smb_host.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
                           r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")


def _looks_like_hostname(name: str) -> bool:
    return bool(_HOSTNAME_RE.match(name))
