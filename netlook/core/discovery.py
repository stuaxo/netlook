"""Discovery engines: independent strategies for finding candidate hosts on the
local network and feeding them to a scanner context.

NetworkScanner (scanner.py) is the only thing that knows how a target becomes
a Device/Service - engines here only call the narrow ScannerContext interface,
never touch Device/Service directly, and have no dependency on dearpygui.

Two shapes of target flow through that interface:
  - A live mDNS service (MdnsDiscovery): full protocol detail via
    `scanner_ctx.discover_mdns_service(zc, type_, name)`.
  - A bare candidate host (SshKnownHostsDiscovery, EtcHostsDiscovery): an IP
    and maybe a name, via `scanner_ctx.queue_probe(ip, hostname, source)` -
    the scanner's existing port probing takes it from there.

Everything runs on a single asyncio event loop (see scanner.py's module
docstring), so no locking is needed for shared state. Note: zeroconf's
AsyncServiceBrowser fires ServiceListener handlers (add_service/
update_service) synchronously, not as coroutines - a plain Signal.fire(), not
awaited - so those handlers just schedule the real async work via
asyncio.create_task() instead of awaiting it inline.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
import uuid
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import httpx
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery
from zeroconf import InterfaceChoice, ServiceListener
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

SERVICE_TYPES = [
    "_workstation._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_device-info._tcp.local.",
    "_home-assistant._tcp.local.",
    "_hue._tcp.local.",
    "_rfb._tcp.local.",  # VNC / macOS Screen Sharing
    "_ipp._tcp.local.",  # IPP printer sharing
    "_ipps._tcp.local.",  # IPP over TLS
    "_printer._tcp.local.",  # legacy LPD/LPR
    "_pdl-datastream._tcp.local.",  # raw/AppSocket/JetDirect printing
]

DNS_SD_META = "_services._dns-sd._udp.local."


class ScannerContext(Protocol):
    """The narrow slice of NetworkScanner discovery engines are allowed to touch."""

    async def queue_probe(self, ip: str, hostname: str | None = None, source: str = "") -> None:
        """Register `ip` (optionally naming it, tagged with `source` for the
        provenance tooltips) as a probe target, and schedule its one-time port probe."""
        ...

    async def discover_mdns_service(self, zc: AsyncZeroconf, type_: str, name: str) -> None:
        """Turn one live mDNS service announcement into Device/Service state."""
        ...


class DiscoveryEngine:
    """Base for a discovery strategy: something that finds candidate hosts and feeds
    them to a scanner context, without needing to know how it turns them into
    Device/Service state."""

    async def start(self, scanner_ctx: ScannerContext) -> None:
        raise NotImplementedError

    async def stop(self) -> None:
        pass  # default: nothing running to tear down


class _TypeListener(ServiceListener):
    """Feeds newly-discovered service *type* strings back to MdnsDiscovery, so
    it can browse types beyond the SERVICE_TYPES list as they're announced."""

    def __init__(self, discovery: "MdnsDiscovery"):
        self.discovery = discovery

    def add_service(self, zc, type_, name):
        self.discovery._browse_type(name)

    def update_service(self, zc, type_, name):
        self.discovery._browse_type(name)

    def remove_service(self, zc, type_, name):
        pass


class MdnsDiscovery(DiscoveryEngine, ServiceListener):
    """Wraps zeroconf's AsyncServiceBrowser/ServiceListener machinery. Live,
    continuous - stop() closes the AsyncZeroconf instance, which tears down its
    background listeners."""

    # Unlike the other engines' SOURCE, never attached to a name in
    # Device.names (discover_mdns_service tags names with the reporting
    # service's own kind, e.g. "ssh" - see models._NON_MDNS_NAME_SOURCES).
    # Only used as this engine's identity in FINDER_SOURCES/Device.found_by,
    # the Properties tab's "Finders" section.
    SOURCE = "mdns"

    def __init__(self, service_types: list[str] | None = None):
        self.service_types = service_types or SERVICE_TYPES
        self.known_types: set[str] = set(self.service_types)
        self.extra_browsers: list[AsyncServiceBrowser] = []
        self._scanner_ctx: ScannerContext | None = None
        self.azc: AsyncZeroconf | None = None
        self.browser: AsyncServiceBrowser | None = None
        self.type_browser: AsyncServiceBrowser | None = None

    async def start(self, scanner_ctx: ScannerContext) -> None:
        self._scanner_ctx = scanner_ctx
        self.azc = AsyncZeroconf(interfaces=InterfaceChoice.All)
        self.browser = AsyncServiceBrowser(self.azc.zeroconf, self.service_types, self)
        # Discovers any other service type in use on the network as it's announced,
        # so we're not limited to the types listed above.
        self.type_browser = AsyncServiceBrowser(self.azc.zeroconf, DNS_SD_META, _TypeListener(self))

    async def stop(self) -> None:
        if self.azc:
            await self.azc.async_close()

    def _browse_type(self, type_name: str) -> None:
        if type_name in self.known_types:
            return
        self.known_types.add(type_name)
        self.extra_browsers.append(AsyncServiceBrowser(self.azc.zeroconf, type_name, self))

    # ServiceListener protocol - zeroconf calls these directly on us, synchronously
    # (see the module docstring), so each just schedules the real async work as a
    # task on the loop we're already running on rather than awaiting it inline.
    def add_service(self, zc, type_, name):
        asyncio.create_task(self._scanner_ctx.discover_mdns_service(self.azc, type_, name))

    def update_service(self, zc, type_, name):
        asyncio.create_task(self._scanner_ctx.discover_mdns_service(self.azc, type_, name))

    def remove_service(self, zc, type_, name):
        pass  # mDNS goodbye packets are flaky; keep last-known state instead of pruning


_WSD_GET_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap:Header>
    <wsa:To>{xaddr}</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
    <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>
    <wsa:ReplyTo>
      <wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>"""


async def _fetch_wsd_friendly_name(xaddr: str) -> str | None:
    """Best-effort WS-Transfer "Get" against a WSD device's XAddr - the metadata
    exchange step (Devices Profile for Web Services, not plain WS-Discovery)
    that Windows Explorer and Samba's wsdd both use to turn an endpoint UUID
    into a computer name. Returns None on failure; WsdDiscovery falls back to
    the EPR."""
    parsed = urlparse(xaddr)
    if not parsed.hostname:
        return None
    body = _WSD_GET_ENVELOPE.format(xaddr=xaddr, message_id=uuid.uuid4()).encode()
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            response = await client.post(
                f"http://{parsed.hostname}:{parsed.port or 80}{parsed.path or '/'}",
                content=body,
                headers={"Content-Type": "application/soap+xml"},
            )
            data = response.content
    except (OSError, httpx.HTTPError):
        return None
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    # namespace-agnostic: DPWS implementations vary in prefix, not in local name
    for el in root.iter():
        if el.tag.endswith("FriendlyName") and el.text and el.text.strip():
            return el.text.strip()
    return None


async def _pick_address(xaddrs: list[str]) -> tuple[str, str] | None:
    """Picks one best address from a WSD service's XAddrs.

    A WSD service can list several XAddrs for the same endpoint - commonly an
    IPv6 link-local address alongside the real LAN IP. Probing all of them
    would create duplicate rows for one device, so this prefers IPv4, skips
    link-local, and falls back to whatever's left. Returns (ip, xaddr), or
    None if nothing usable was found.

    Always returns a literal IP, never a raw hostname: some WSD responders
    (Samba's wsdd) advertise a bare hostname instead (e.g.
    "http://werner:5357/..."). Keying the Device by that hostname would stop
    it merging with the same host found via mDNS/smb, which key by IP. A
    hostname-only XAddr is resolved via _resolve_local_hostname as a last
    resort; if that fails too, it's dropped."""
    ip_candidates = []
    hostname_candidates = []
    for xaddr in xaddrs:
        host = urlparse(xaddr).hostname
        if not host:
            continue
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            hostname_candidates.append((host, xaddr))
            continue
        if addr.is_link_local:
            continue
        ip_candidates.append((1 if addr.version == 6 else 0, host, xaddr))

    if ip_candidates:
        _, ip, xaddr = min(ip_candidates, key=lambda c: c[0])  # IPv4 (0) before IPv6 (1)
        return ip, xaddr

    for host, xaddr in hostname_candidates:
        resolved = await _resolve_local_hostname(host)
        if resolved:
            return resolved, xaddr
    return None


class WsdDiscovery(DiscoveryEngine):
    """Web Services Discovery (WSD) - how Windows machines and Samba (wsdd)
    advertise themselves, since neither speaks mDNS.

    wsdiscovery has no async API of its own (searchServices() is a blocking,
    one-shot call), so each poll runs it in a worker thread via
    asyncio.to_thread(); the polling loop itself is a native asyncio task."""

    SOURCE = "WSD"
    POLL_INTERVAL = 60  # seconds between re-probes, to notice devices that join later

    def __init__(self, poll_interval: float = POLL_INTERVAL):
        self.poll_interval = poll_interval
        self._wsd: WSDiscovery | None = None
        self._scanner_ctx: ScannerContext | None = None
        self._task: asyncio.Task | None = None

    async def start(self, scanner_ctx: ScannerContext) -> None:
        self._scanner_ctx = scanner_ctx
        self._wsd = WSDiscovery()
        self._wsd.start()
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self._wsd:
            # ThreadedWSDiscovery.stop() joins its internal threads synchronously,
            # which blocks for about their ~1s poll interval. They're already
            # daemon threads, so nothing leaks if the process exits first - not
            # worth making our own shutdown wait on a foreign library's teardown,
            # especially right after start() when searchServices() may still be
            # mid-flight in a to_thread worker.
            threading.Thread(target=self._wsd.stop, daemon=True).start()

    async def _poll_loop(self) -> None:
        while True:
            services = await asyncio.to_thread(self._wsd.searchServices)
            for service in services:
                await self._report(service)
            await asyncio.sleep(self.poll_interval)

    async def _report(self, service) -> None:
        picked = await _pick_address(service.getXAddrs())
        if not picked:
            return
        ip, xaddr = picked
        epr = service.getEPR()
        fallback_name = epr.removeprefix("urn:uuid:") if epr else None
        name = await _fetch_wsd_friendly_name(xaddr) or fallback_name
        await self._scanner_ctx.queue_probe(ip, name, source=self.SOURCE)


def _is_local(addr: str) -> bool:
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_link_local


async def _resolve_local_hostname(hostname: str) -> str | None:
    try:
        return await asyncio.to_thread(socket.gethostbyname, hostname)
    except OSError:
        return None  # no .local resolver available (e.g. no avahi/nss-mdns) - skip it


_reverse_hostname_cache: dict[str, str | None] = {}


async def _resolve_reverse_hostname(ip: str) -> str | None:
    """Best-effort PTR/reverse-mDNS lookup, so an address with no name of its
    own (e.g. from ArpCacheDiscovery) can show as more than a bare IP.
    nss-mdns wires this into gethostbyaddr() for .local addresses, same as
    the forward lookup in _resolve_local_hostname.

    Cached per IP for the process's lifetime: ArpCacheDiscovery and the
    Properties tab's DNS section (NetworkScanner.ensure_dns_resolved) can
    both ask about the same address, and a real PTR lookup is a network
    round trip worth not repeating in quick succession."""
    if ip in _reverse_hostname_cache:
        return _reverse_hostname_cache[ip]
    try:
        name, _aliases, _ips = await asyncio.to_thread(socket.gethostbyaddr, ip)
    except OSError:
        name = None  # no reverse entry available - the caller falls back to the IP
    _reverse_hostname_cache[ip] = name
    return name


async def _parse_known_hosts(path: Path) -> AsyncIterator[tuple[str, str | None]]:
    """Yields (ip, hostname) for unhashed .local hostnames and local IPs in an
    OpenSSH known_hosts file. Hashed entries (HashKnownHosts, the default on
    most distros) can't be reversed, so lines starting with "|" are skipped.

    The file read is a plain synchronous call - negligible-cost, one-shot,
    not worth asyncio.to_thread. Resolving a .local hostname is a real
    network round-trip though, so that part is async."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("|"):
            continue
        hosts_field = line.split(None, 1)[0]  # "host1,host2[,ip] key-type key [comment]"
        for token in hosts_field.split(","):
            token = token.split("]")[0].removeprefix("[")  # "[host]:2222" -> "host"
            if token.endswith(".local"):
                ip = await _resolve_local_hostname(token)
                if ip:
                    yield ip, token
            elif _is_local(token):
                yield token, None


class SshKnownHostsDiscovery(DiscoveryEngine):
    """One-shot: reads ~/.ssh/known_hosts at start() and queues whatever unhashed
    .local hostnames or local IPs it finds for probing. known_hosts only changes when
    you ssh somewhere new, so there's nothing to watch continuously."""

    SOURCE = "ssh-known-hosts"

    def __init__(self, path: Path | None = None):
        self.path = path or Path.home() / ".ssh" / "known_hosts"

    async def start(self, scanner_ctx: ScannerContext) -> None:
        async for ip, hostname in _parse_known_hosts(self.path):
            await scanner_ctx.queue_probe(ip, hostname, source=self.SOURCE)


def _parse_etc_hosts(path: Path) -> list[tuple[str, str]]:
    """Returns (ip, alias) pairs for each non-loopback, local /etc/hosts line -
    one pair per alias, since a line can list several names for one IP.

    Synchronous like _parse_known_hosts, but simpler: no per-entry resolution
    here, so nothing async to yield control around."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_text, aliases = parts[0], parts[1:]
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if addr.is_loopback or not _is_local(ip_text):
            continue
        for alias in aliases:
            entries.append((ip_text, alias))
    return entries


class EtcHostsDiscovery(DiscoveryEngine):
    """One-shot: reads /etc/hosts at start() and queues its static local entries for
    probing (loopback and non-local lines filtered out - probing a public IP someone
    happened to hardcode isn't this tool's job)."""

    SOURCE = "etc-hosts"

    def __init__(self, path: Path | None = None):
        self.path = path or Path("/etc/hosts")

    async def start(self, scanner_ctx: ScannerContext) -> None:
        for ip, alias in _parse_etc_hosts(self.path):
            await scanner_ctx.queue_probe(ip, alias, source=self.SOURCE)


def _parse_arp_cache(path: Path) -> list[str]:
    """Returns local IPv4 addresses with a complete (link-layer-resolved) entry
    in the Linux kernel's ARP cache (/proc/net/arp), e.g.
    "192.168.1.253  0x1  0x2  9c:bf:0d:00:f2:db  *  eth0". Incomplete entries
    (flags "0x0", zero hardware address - no reply from the address) are
    skipped. Returns [] on any read failure, including the file not existing
    on non-Linux platforms."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    addresses = []
    for line in lines[1:]:  # header row: "IP address  HW type  Flags  HW address ..."
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_text, flags, hw_addr = parts[0], parts[2], parts[3]
        if flags == "0x0" or hw_addr == "00:00:00:00:00:00":
            continue
        if _is_local(ip_text):
            addresses.append(ip_text)
    return addresses


class ArpCacheDiscovery(DiscoveryEngine):
    """One-shot: reads the Linux kernel's ARP cache (/proc/net/arp) at start()
    and queues local, link-layer-resolved addresses for probing.

    Catches hosts the machine has already exchanged packets with (a prior
    ping or ssh session), even when they never announce via mDNS/WSD and
    aren't in known_hosts or /etc/hosts - a device that only answers plain
    A-record queries, with no service records, is otherwise invisible to
    MdnsDiscovery. Linux-only: /proc/net/arp doesn't exist elsewhere, so this
    quietly finds nothing there."""

    SOURCE = "arp-cache"

    def __init__(self, path: Path | None = None):
        self.path = path or Path("/proc/net/arp")

    async def start(self, scanner_ctx: ScannerContext) -> None:
        for ip in _parse_arp_cache(self.path):
            hostname = await _resolve_reverse_hostname(ip)
            await scanner_ctx.queue_probe(ip, hostname, source=self.SOURCE)


# (display label, SOURCE) for every engine, in the same order NetworkScanner's
# _default_discovery_engines lists them - the Properties tab's "Finders" section
# (Device.found_by, populated in scanner.py's queue_probe/discover_mdns_service)
# renders exactly this list, one Found/Not Found row per entry, for every device.
FINDER_SOURCES: list[tuple[str, str]] = [
    ("mDNS", MdnsDiscovery.SOURCE),
    ("SSH known_hosts", SshKnownHostsDiscovery.SOURCE),
    ("/etc/hosts", EtcHostsDiscovery.SOURCE),
    ("WSD", WsdDiscovery.SOURCE),
    ("ARP cache", ArpCacheDiscovery.SOURCE),
]
