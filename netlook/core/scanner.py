"""The network engine: NetworkScanner is the central orchestrator. It owns
the Device tree and a list of DiscoveryEngine instances (discovery.py) that
feed it candidate hosts, and does the active port-probing/protocol
verification itself, since that's shared infrastructure every engine's
targets flow through.

No UI toolkit dependency. No direct zeroconf dependency either - discovery.py
owns all zeroconf usage - just stdlib, httpx, and models.py.

Everything runs on a single asyncio event loop, so there's no lock anywhere:
a coroutine only yields control at an `await`, so any synchronous
check-then-mutate sequence with no `await` in between is already atomic. A
frontend reading this scanner's state from a different thread (a synchronous
UI toolkit bridging into this event loop) is responsible for its own
cross-thread synchronization - not this module's concern.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import xml.etree.ElementTree as ET

import httpx
import psutil

from .discovery import (
    ArpCacheDiscovery,
    DiscoveryEngine,
    EtcHostsDiscovery,
    MdnsDiscovery,
    SshKnownHostsDiscovery,
    WsdDiscovery,
)
from .models import Device, Fetchable, FetchState, Service, kind_from_type


def _detect_local_network() -> tuple[set[str], str]:
    """Every IPv4 address bound to a local interface (including loopback), and
    which one to treat as canonical - the address other devices on the LAN
    would use to reach this machine.

    Used to recognise a discovered device as this machine, so it collapses
    into one Device entry instead of a row per interface (e.g. LAN address
    and 127.0.0.1 as two unrelated devices).

    0.0.0.0 is excluded even though psutil.net_if_addrs() doesn't normally
    report it - a misconfigured interface could still report it, and it's
    not a genuine connectable identity of this machine."""
    local_ips = {"127.0.0.1"}
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "0.0.0.0":
                local_ips.add(addr.address)

    canonical = None
    try:
        # A UDP "connect" never actually sends a packet - it just asks the kernel
        # to pick the route/interface it would use, which is exactly the address
        # other devices on the LAN would see this machine as.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            canonical = s.getsockname()[0]
    except OSError:
        pass
    if not canonical or canonical not in local_ips:
        canonical = next((ip for ip in local_ips if ip != "127.0.0.1"), "127.0.0.1")

    return local_ips, canonical


_NULL_MAC = "00:00:00:00:00:00"


def _detect_local_physical_interfaces() -> list[tuple[str, str]]:
    """This machine's network interfaces with a real hardware (MAC) address -
    (interface name, mac) pairs, e.g. [("wlp192s0", "6e:3a:...")].

    Loopback reports psutil.AF_LINK too, but with the null MAC
    00:00:00:00:00:00 - excluded since it's virtual, not a physical device."""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK and a.address), None)
        if mac and mac != _NULL_MAC:
            interfaces.append((name, mac))
    return interfaces

# Each value is a port spec: comma-separated ports and/or "start-end" ranges, e.g.
# "22,2022" or "3389-3391". Every candidate port is tried in order; the first one
# that verifies wins and probing for that kind stops there.
# vnc: 5900 + display number, so 5900-5902 covers displays :0-:2, the common case
# moonlight: GameStream/Sunshine's HTTP port, then its HTTPS one - /serverinfo is
# served on both, so either being open is enough to try it
PROBE_PORTS = {
    "ssh": "22,2022", "rdp": "3389-3391", "incus": "8443", "cups": "631", "vnc": "5900-5902",
    "moonlight": "47989,47984",
}


def _parse_ports(spec: str) -> list[int]:
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


PROBE_PORT_LISTS = {kind: _parse_ports(spec) for kind, spec in PROBE_PORTS.items()}

# A bare open port doesn't mean the expected service is behind it (e.g. plenty of
# devices have *something* on 8443 that isn't incus), so each probed port gets a
# protocol-level check rather than just a TCP connect.

# Minimal RDP X.224 Connection Request; a real RDP server replies with an X.224
# Connection Confirm (TPDU code 0xd0). Same probe nmap/rdp scanners use.
_RDP_NEGOTIATION_REQUEST = bytes.fromhex("030000130ee000000000000100080000000000")

_PROBE_TIMEOUT = 1.5


async def _verify_ssh(ip: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        banner = await asyncio.wait_for(reader.read(64), timeout=_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
    return banner.startswith(b"SSH-")


async def _verify_rdp(ip: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(_RDP_NEGOTIATION_REQUEST)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(19), timeout=_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
    return len(resp) >= 6 and resp[:2] == b"\x03\x00" and resp[5] == 0xD0


async def incus_get(ip: str, port: int, path: str) -> dict | None:
    """Shared by _verify_incus (below) and services.Incus.fetch - both need "an
    authenticated-enough HTTPS GET against an incus/LXD host, parsed as JSON"."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=_PROBE_TIMEOUT) as client:
            response = await client.get(f"https://{ip}:{port}{path}")
            data = response.content
    except (OSError, httpx.HTTPError):
        return None
    try:
        return json.loads(data)
    except ValueError:
        return None


async def _verify_incus(ip: str, port: int) -> bool:
    """incus/LXD expose an unauthenticated GET /1.0 with a distinctive JSON body."""
    metadata = (await incus_get(ip, port, "/1.0") or {}).get("metadata")
    return isinstance(metadata, dict) and "api_extensions" in metadata


async def _verify_cups(ip: str, port: int) -> bool:
    """CUPS' embedded httpd always identifies itself in the Server header."""
    try:
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT) as client:
            response = await client.get(f"http://{ip}:{port}/")
            server = response.headers.get("Server", "")
    except (OSError, httpx.HTTPError):
        return False
    return "CUPS" in server


async def _verify_vnc(ip: str, port: int) -> bool:
    """VNC/RFB servers (incl. macOS Screen Sharing) send a "RFB xxx.yyy\\n" version
    banner as the very first thing on connect, no request needed - RFC 6143 §7.1.1."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        banner = await asyncio.wait_for(reader.read(12), timeout=_PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
    return banner.startswith(b"RFB ")


async def _moonlight_serverinfo(ip: str, port: int) -> bytes | None:
    # GameStream/Sunshine serve the same /serverinfo over plain HTTP or HTTPS
    # depending on setup/port - try both rather than assuming one.
    for scheme, verify in (("http", True), ("https", False)):
        try:
            async with httpx.AsyncClient(verify=verify, timeout=_PROBE_TIMEOUT) as client:
                response = await client.get(f"{scheme}://{ip}:{port}/serverinfo")
                return response.content
        except (OSError, httpx.HTTPError):
            continue
    return None


async def _verify_moonlight(ip: str, port: int) -> bool:
    """GameStream/Sunshine (what Moonlight clients connect to) expose an
    unauthenticated GET /serverinfo with a distinctive XML body."""
    data = await _moonlight_serverinfo(ip, port)
    if not data:
        return False
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return False
    return root.tag == "root" and root.find("uniqueid") is not None


PROBE_VERIFIERS = {
    "ssh": _verify_ssh, "rdp": _verify_rdp, "incus": _verify_incus, "cups": _verify_cups, "vnc": _verify_vnc,
    "moonlight": _verify_moonlight,
}


def _split_addresses(addresses: list) -> tuple:
    """First IPv4 and first IPv6 address found, either may be None."""
    ip4 = ip6 = None
    for addr in addresses:
        version = ipaddress.ip_address(addr).version
        if version == 4 and ip4 is None:
            ip4 = addr
        elif version == 6 and ip6 is None:
            ip6 = addr
    return ip4, ip6


def _default_discovery_engines() -> list[DiscoveryEngine]:
    return [
        MdnsDiscovery(),
        SshKnownHostsDiscovery(),
        EtcHostsDiscovery(),
        WsdDiscovery(),
        ArpCacheDiscovery(),
    ]


class NetworkScanner:
    def __init__(self, discovery_engines: list[DiscoveryEngine] | None = None,
                 local_network: tuple[set[str], str] | None = None,
                 local_physical_interfaces: list[tuple[str, str]] | None = None):
        self.devices: dict[str, Device] = {}
        self.probed: set[str] = set()
        self.dirty = True
        self.discovery_engines = discovery_engines if discovery_engines is not None else _default_discovery_engines()
        self._tasks: set[asyncio.Task] = set()
        self._probe_semaphore = asyncio.Semaphore(3)
        # Injectable (like discovery_engines) so tests can exercise the local-machine
        # merge/naming logic deterministically, without depending on whatever real
        # interfaces happen to be present on the machine running the test suite.
        self._local_ips, self._local_canonical_ip = local_network if local_network is not None \
            else _detect_local_network()
        self._local_physical_interfaces = local_physical_interfaces if local_physical_interfaces is not None \
            else _detect_local_physical_interfaces()

    def _canonicalize_ip(self, ip: str) -> str:
        """Maps any of this machine's interface addresses to
        _local_canonical_ip, so this box - reachable at several addresses -
        collapses into a single Device entry via devices.setdefault(ip, ...)
        rather than a row per interface."""
        return self._local_canonical_ip if ip in self._local_ips else ip

    async def start(self) -> None:
        # Pre-seed this machine's entry with "localhost", so it's present
        # before any discovery engine reports anything - a nicer name found
        # later (e.g. this box's own _device-info._tcp) promotes over it
        # without losing it, like any other alias.
        self.devices.setdefault(
            self._local_canonical_ip,
            Device("localhost", self._local_canonical_ip, names={"localhost": {"localhost"}},
                   physical_interfaces=self._local_physical_interfaces),
        )
        await self._ensure_probed(self._local_canonical_ip)
        for engine in self.discovery_engines:
            await engine.start(self)

    async def close(self) -> None:
        for engine in self.discovery_engines:
            await engine.stop()
        for task in list(self._tasks):
            task.cancel()

    def _track(self, coro) -> asyncio.Task:
        """Schedules background probe/fetch work as a tracked task, so close() can
        cancel anything still in flight instead of leaking it."""
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def request_items(self, service: Service, **kwargs) -> None:
        """Kicks off whatever async fetch a service's resources() needs (a
        share list, an instance list, ...).

        Unconditional - runs regardless of fetch_state, since a caller
        reaching for this rather than ensure_fetched already wants a
        specific fetch now, e.g. a credentialed retry after AUTH_REQUIRED."""
        if service.loading:
            return
        service.loading = True
        self.dirty = True  # show "loading" immediately
        self._track(self._fetch_items(service, kwargs))

    async def ensure_fetched(self, service: Service) -> None:
        """Lazily triggers service.fetch() the first time something expresses
        interest (e.g. a device row expands) - a no-op if already attempted.

        The caller just says "I want this now"; whether it becomes a real
        fetch is this scanner's call, based on fetch_state."""
        if isinstance(service, Fetchable) and service.fetch_state == FetchState.NOT_FETCHED:
            await self.request_items(service)

    async def _fetch_items(self, service: Service, kwargs: dict) -> None:
        await service.fetch(**kwargs)
        self.dirty = True

    async def wait_idle(self) -> None:
        """Waits for every tracked background task (probes, fetches) to finish.

        request_items()/_ensure_probed() schedule work rather than awaiting
        it, so a caller is never blocked on a slow fetch. This is how a
        caller that does need the result (e.g. a test observing a scheduled
        fetch deterministically) can wait for it to land."""
        tasks = [t for t in self._tasks if not t.done()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def queue_probe(self, ip: str, hostname: str | None = None, source: str = "") -> None:
        """ScannerContext entry point for discovery engines that only know
        "here's a candidate host" (ssh known_hosts, /etc/hosts, ...), unlike
        mDNS's full service detail. Registers the target and name (tagged
        with `source` for provenance tooltips) and schedules its one-time
        port probe."""
        ip = self._canonicalize_ip(ip)
        device = self.devices.setdefault(ip, Device(hostname or ip, ip, names={(hostname or ip): {source}}))
        if hostname:
            device.add_alias(source, hostname)
        if source:
            device.found_by.add(source)
        self.dirty = True
        await self._ensure_probed(ip)

    async def discover_mdns_service(self, zc, type_, name) -> None:
        """ScannerContext entry point for MdnsDiscovery: turn one live mDNS service
        announcement into Device/Service state."""
        info = await zc.async_get_service_info(type_, name)
        if not info or not info.parsed_addresses():
            return
        ip4, ip6 = _split_addresses(info.parsed_addresses())
        ip = self._canonicalize_ip(ip4 or ip6) if (ip4 or ip6) else None
        if not ip:
            return
        discovered_name = name.split(".")[0]
        kind = kind_from_type(type_)

        device = self.devices.setdefault(
            ip, Device(discovered_name, ip, names={discovered_name: {kind}})
        )
        if ip6 and not device.ipv6:
            device.ipv6 = ip6
        device.add_service(type_, info.port, info.properties, discovered_name)
        device.found_by.add(MdnsDiscovery.SOURCE)
        self.dirty = True

        await self._ensure_probed(ip)

    async def _ensure_probed(self, ip: str) -> None:
        """Schedules a one-time port probe for `ip`, whichever engine found
        it - "have we probed this yet" bookkeeping lives here so every
        engine's targets flow through the same probing logic.

        For this machine's own canonical entry, also tries 127.0.0.1
        alongside the LAN address: a loopback-only service (CUPS often
        defaults to this) would never answer on the LAN address, and would
        otherwise be invisible on the device meant to represent the whole
        machine."""
        if ip in self.probed:
            return
        self.probed.add(ip)
        connect_ips = [ip, "127.0.0.1"] if ip == self._local_canonical_ip else [ip]
        self._track(self._probe(ip, connect_ips))

    async def _probe(self, ip: str, connect_ips: list[str] | None = None):
        connect_ips = connect_ips or [ip]
        async with self._probe_semaphore:
            known = set(self.devices[ip].services)
            for kind, ports in PROBE_PORT_LISTS.items():
                if kind in known:
                    continue
                verifier = PROBE_VERIFIERS[kind]
                found = False
                for connect_ip in connect_ips:
                    for port in ports:
                        if not await verifier(connect_ip, port):
                            continue
                        if ip in self.devices:
                            self.devices[ip].add_service(kind, port, ip=connect_ip)
                            self.dirty = True
                        found = True
                        break
                    if found:
                        break  # this kind is now known - stop trying other connect_ips too
