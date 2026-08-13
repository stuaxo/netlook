"""Unit tests for netlook.core.scanner."""
import json
import socket

import pytest

from netlook.core import discovery, scanner
from netlook.core.models import Device, FetchState
from netlook.core.scanner import _parse_ports, _split_addresses

from doubles import FakeFetchable, FetchRecordingService


@pytest.mark.parametrize("spec, expected_ports", [
    ("22", [22]),
    ("22,2022", [22, 2022]),
    ("3389-3391", [3389, 3390, 3391]),
    ("22, 2022 , 8000-8002", [22, 2022, 8000, 8001, 8002]),
])
def test_parse_ports_expands_lists_and_ranges(spec, expected_ports):
    """Verify that _parse_ports expands a comma-separated spec of ports and/or
    "start-end" ranges into a flat list of ints, by checking several combined
    forms."""
    ports = _parse_ports(spec)

    assert ports == expected_ports


@pytest.mark.parametrize("addresses, expected", [
    (["10.0.0.5"], ("10.0.0.5", None)),
    (["fe80::1"], (None, "fe80::1")),
    (["10.0.0.5", "fe80::1"], ("10.0.0.5", "fe80::1")),
    (["10.0.0.5", "10.0.0.6"], ("10.0.0.5", None)),
])
def test_split_addresses_picks_first_ipv4_and_first_ipv6(addresses, expected):
    """Verify that _split_addresses returns the first IPv4 and first IPv6 address
    found and ignores extras of either family, by checking several address mixes."""
    result = _split_addresses(addresses)

    assert result == expected


async def test_queue_probe_seeds_a_new_device_with_the_given_hostname(net_scanner):
    """Verify that queue_probe creates a Device using the given hostname as its
    primary name and records the source, by checking the resulting Device."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts")

    device = net_scanner.devices["192.168.1.50"]
    assert device.hostname == "nas.lan"
    assert device.names == {"nas.lan": {"etc-hosts"}}


async def test_queue_probe_falls_back_to_the_bare_ip_when_no_hostname_is_given(net_scanner):
    """Verify that queue_probe seeds the device's hostname with its own IP when no
    hostname is supplied, by checking a pure-IP known_hosts-style entry."""
    await net_scanner.queue_probe("192.168.1.77", None, source="ssh-known-hosts")

    assert net_scanner.devices["192.168.1.77"].hostname == "192.168.1.77"


async def test_queue_probe_merges_sources_when_two_engines_report_the_same_name(net_scanner):
    """Verify that queue_probe merges provenance sources into one names[] entry
    rather than creating a duplicate alias, by calling it twice with different
    sources for the same host/name pair."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts")
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="ssh-known-hosts")

    assert net_scanner.devices["192.168.1.50"].names == {"nas.lan": {"etc-hosts", "ssh-known-hosts"}}


async def test_queue_probe_canonicalizes_a_local_machine_ip(net_scanner):
    """Verify that queue_probe folds a known local-machine IP (loopback, here -
    net_scanner's fixture local_network is {"127.0.0.1", "192.168.99.1"}) into the
    canonical one, so this machine's own loopback and LAN addresses collapse into
    one Device instead of showing up as two separate, unrelated ones."""
    await net_scanner.queue_probe("127.0.0.1", "some-loopback-name", source="etc-hosts")

    assert "127.0.0.1" not in net_scanner.devices
    assert net_scanner.devices["192.168.99.1"].hostname == "some-loopback-name"


async def test_queue_probe_records_its_source_in_found_by(net_scanner):
    """Verify that queue_probe adds its `source` to the device's found_by set,
    independent of naming - the Properties tab's "Finders" section reads this,
    not `names`, so it still marks the device Found even when no hostname was
    given (see test_queue_probe_falls_back_to_the_bare_ip_when_no_hostname_is_given)."""
    await net_scanner.queue_probe("192.168.1.77", None, source="arp-cache")

    assert net_scanner.devices["192.168.1.77"].found_by == {"arp-cache"}


async def test_queue_probe_seeds_the_new_devices_own_ip_into_its_addresses(net_scanner):
    """Verify that queue_probe records a brand-new device's own ip in
    Device.addresses from the start, tagged with the source that reported
    it - mirroring how its hostname is seeded into `names` at the same time
    - so `addresses` is a complete record for every device, not just this
    machine's own (see NetworkScanner.start's local-interface seeding)."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts")

    assert net_scanner.devices["192.168.1.50"].addresses == {"192.168.1.50": {"etc-hosts"}}


async def test_queue_probe_with_a_known_mac_folds_a_second_address_into_the_first(net_scanner):
    """Verify that a second queue_probe call reporting the same MAC as an
    already-known device's - even under a completely different ip and
    source - folds into that device's row instead of creating a second,
    duplicate one. This is the general case _canonicalize_ip only handles for
    this machine's own addresses, extended to any device via ARP evidence."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts", mac="aa:bb:cc:dd:ee:ff")
    await net_scanner.queue_probe("192.168.1.51", "nas-wifi", source="arp-cache", mac="aa:bb:cc:dd:ee:ff")

    assert set(net_scanner.devices) == {"192.168.1.50"}
    device = net_scanner.devices["192.168.1.50"]
    assert device.addresses == {
        "192.168.1.50": {"etc-hosts"},
        "192.168.1.51": {"arp-cache"},
    }
    assert device.aliases == {"nas-wifi": {"arp-cache"}}


async def test_queue_probe_with_different_macs_creates_separate_devices(net_scanner):
    """Verify that two addresses reporting two different MACs stay two separate
    devices - MAC evidence only folds addresses together when it actually
    agrees they're the same host."""
    await net_scanner.queue_probe("192.168.1.50", "nas", source="arp-cache", mac="aa:bb:cc:dd:ee:ff")
    await net_scanner.queue_probe("192.168.1.51", "printer", source="arp-cache", mac="11:22:33:44:55:66")

    assert set(net_scanner.devices) == {"192.168.1.50", "192.168.1.51"}


async def test_queue_probe_merges_two_already_materialized_devices_on_late_mac_evidence(net_scanner):
    """Verify that when two rows were already created independently (e.g. one
    from /etc/hosts, one from ssh known_hosts, each with no MAC available at
    the time) and the ARP cache later reveals they share a MAC, the two rows
    merge into one - names, addresses, and found_by from both survive on the
    surviving row, and the other disappears from `devices` entirely."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts")
    await net_scanner.queue_probe("192.168.1.51", "nas-wifi", source="ssh-known-hosts")

    await net_scanner.queue_probe("192.168.1.50", None, source="arp-cache", mac="aa:bb:cc:dd:ee:ff")
    await net_scanner.queue_probe("192.168.1.51", None, source="arp-cache", mac="aa:bb:cc:dd:ee:ff")

    assert set(net_scanner.devices) == {"192.168.1.50"}
    device = net_scanner.devices["192.168.1.50"]
    assert device.names == {"nas.lan": {"etc-hosts"}, "nas-wifi": {"ssh-known-hosts"}}
    assert device.addresses == {
        "192.168.1.50": {"etc-hosts", "arp-cache"},
        "192.168.1.51": {"ssh-known-hosts", "arp-cache"},
    }
    assert device.found_by == {"etc-hosts", "ssh-known-hosts", "arp-cache"}


async def test_queue_probe_resolves_through_a_previously_learned_address_without_a_mac(net_scanner):
    """Verify that once ARP evidence has linked a secondary address to a
    device, a later report of that same address with no MAC at all (e.g.
    /etc/hosts, which never has one) still resolves to the right device -
    the mapping learned via MAC persists independent of whether every later
    sighting repeats it."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts", mac="aa:bb:cc:dd:ee:ff")
    await net_scanner.queue_probe("192.168.1.51", None, source="arp-cache", mac="aa:bb:cc:dd:ee:ff")

    await net_scanner.queue_probe("192.168.1.51", "nas-wifi.lan", source="etc-hosts")

    assert set(net_scanner.devices) == {"192.168.1.50"}
    assert net_scanner.devices["192.168.1.50"].aliases == {"nas-wifi.lan": {"etc-hosts"}}


async def test_discover_mdns_service_resolves_through_an_already_known_secondary_address(net_scanner, fake_zeroconf):
    """Verify that discover_mdns_service - which never has a MAC of its own -
    still folds into an existing device when mDNS announces an address ARP
    already linked to one, rather than creating an unrelated second row."""
    await net_scanner.queue_probe("192.168.1.50", "nas.lan", source="etc-hosts", mac="aa:bb:cc:dd:ee:ff")
    await net_scanner.queue_probe("192.168.1.51", None, source="arp-cache", mac="aa:bb:cc:dd:ee:ff")

    zc = fake_zeroconf(addresses=["192.168.1.51"])
    await net_scanner.discover_mdns_service(zc, "_smb._tcp.local.", "MyNAS._smb._tcp.local.")

    assert set(net_scanner.devices) == {"192.168.1.50"}
    device = net_scanner.devices["192.168.1.50"]
    assert "smb" in device.services
    assert device.addresses["192.168.1.51"] == {"arp-cache", "mdns"}


async def test_start_seeds_the_local_machine_device_with_localhost_as_a_name(net_scanner):
    """Verify that start() pre-seeds the canonical local-machine device with
    "localhost" as its hostname and one of its names, so this machine shows up in
    the browser - recognizable as itself - even before any discovery engine or
    probe reports anything about it."""
    await net_scanner.start()

    device = net_scanner.devices["192.168.99.1"]
    assert device.hostname == "localhost"
    assert device.names["localhost"] == {"localhost"}


async def test_start_attaches_interfaces_to_the_local_machine_device():
    """Verify that start() attaches local_interfaces to the seeded local-machine
    device, so a machine with a real network interface shows a Network
    Interfaces section in its own Properties tab."""
    net_scanner = scanner.NetworkScanner(
        discovery_engines=[],
        local_network=({"127.0.0.1", "192.168.99.1"}, "192.168.99.1"),
        local_interfaces=[("wlan0", "aa:bb:cc:dd:ee:ff", ["192.168.99.1"])],
    )

    async def no_probe(ip, connect_ips=None):
        pass

    net_scanner._probe = no_probe
    await net_scanner.start()

    assert net_scanner.devices["192.168.99.1"].interfaces == [("wlan0", "aa:bb:cc:dd:ee:ff", ["192.168.99.1"])]
    await net_scanner.close()


@pytest.mark.parametrize("local_ips, canonical", [
    # This machine's actual interfaces, captured via
    # `_detect_local_network()` while writing this test: one wifi NIC plus
    # loopback - the common single-NIC laptop/desktop case.
    ({"127.0.0.1", "192.168.1.111"}, "192.168.1.111"),
    # A second NIC bound at the same time (wired + wifi, or a VPN/tailscale
    # interface) - more than one non-loopback address alongside loopback.
    ({"127.0.0.1", "192.168.1.111", "10.20.30.5"}, "192.168.1.111"),
    # No non-loopback interface up at all (e.g. offline/airplane mode) -
    # loopback is the only, and therefore canonical, address.
    ({"127.0.0.1"}, "127.0.0.1"),
])
async def test_start_records_every_local_ip_as_an_address_of_the_local_machine_device(local_ips, canonical):
    """Verify that start() records every one of this machine's own local
    addresses - loopback, LAN, and any extra interface - as a `Device.addresses`
    entry on the local-machine device, not just the single canonical `ip`. This
    is the concrete case the addresses feature exists for: one physical machine
    reachable at several addresses should show up as one row that knows about
    all of them, not silently lose all but the canonical one. Parametrized with
    this machine's real interface shape plus two plausible variants (multi-NIC,
    loopback-only)."""
    net_scanner = scanner.NetworkScanner(
        discovery_engines=[], local_network=(local_ips, canonical), local_interfaces=[],
    )

    async def no_probe(ip, connect_ips=None):
        pass

    net_scanner._probe = no_probe
    await net_scanner.start()

    device = net_scanner.devices[canonical]
    assert device.ip == canonical
    assert set(device.addresses) == local_ips
    assert all(device.addresses[ip] == {"local-interface"} for ip in local_ips)
    await net_scanner.close()


async def test_probe_falls_back_to_loopback_for_the_local_machines_own_services(monkeypatch):
    """Verify that probing this machine's own canonical device also tries
    127.0.0.1, recording a found service against whichever address actually
    answered - not blindly against the canonical LAN address - since a service
    bound loopback-only (CUPS's own common default, for security) would otherwise
    never be found via the LAN address at all, and the resulting action needs to
    point at an address that actually works. Regression test: this used to only
    ever probe the canonical LAN address, silently missing services that only
    listen on 127.0.0.1."""
    async def loopback_only_cups(ip, port):
        return ip == "127.0.0.1" and port == 631

    monkeypatch.setitem(scanner.PROBE_VERIFIERS, "cups", loopback_only_cups)
    monkeypatch.setattr(scanner, "PROBE_PORT_LISTS", {"cups": [631]})
    net_scanner = scanner.NetworkScanner(
        discovery_engines=[], local_network=({"127.0.0.1", "192.168.99.1"}, "192.168.99.1"),
    )

    await net_scanner.start()  # creates the local-machine Device and probes it
    await net_scanner.wait_idle()

    device = net_scanner.devices["192.168.99.1"]
    assert "cups" in device.services
    assert device.services["cups"].ip == "127.0.0.1"
    await net_scanner.close()


async def test_probe_prefers_the_lan_address_over_loopback_when_both_answer(monkeypatch):
    """Verify that the LAN address is tried first and wins when a service answers
    on both - loopback is a fallback for what the LAN address alone would miss,
    not a blanket preference."""
    async def answers_everywhere(ip, port):
        return port == 631

    monkeypatch.setitem(scanner.PROBE_VERIFIERS, "cups", answers_everywhere)
    monkeypatch.setattr(scanner, "PROBE_PORT_LISTS", {"cups": [631]})
    net_scanner = scanner.NetworkScanner(
        discovery_engines=[], local_network=({"127.0.0.1", "192.168.99.1"}, "192.168.99.1"),
    )

    await net_scanner.start()  # creates the local-machine Device and probes it
    await net_scanner.wait_idle()

    assert net_scanner.devices["192.168.99.1"].services["cups"].ip == "192.168.99.1"
    await net_scanner.close()


def test_detect_local_interfaces_treats_the_null_mac_as_no_mac(monkeypatch):
    """Verify that _detect_local_interfaces reports the all-zero MAC every OS
    gives loopback as None rather than a real MAC - it's a virtual interface,
    not a physical device - while still including the interface, since its
    address (127.0.0.1) is a genuine one the Network Interfaces section should
    show. A real interface keeps its MAC.

    Fixture shape is this machine's real interfaces, captured via
    `psutil.net_if_addrs()` while writing this test: one wifi NIC (IPv4 +
    IPv6 + MAC) plus loopback (IPv4 + IPv6, null MAC) - IPv6 addresses are
    present in the raw data but not reflected in the result, since interfaces
    only surfaces IPv4."""
    class FakeAddr:
        def __init__(self, family, address):
            self.family = family
            self.address = address

    fake_addrs = {
        "lo": [
            FakeAddr(scanner.socket.AF_INET, "127.0.0.1"),
            FakeAddr(scanner.socket.AF_INET6, "::1"),
            FakeAddr(scanner.psutil.AF_LINK, "00:00:00:00:00:00"),
        ],
        "wlp192s0": [
            FakeAddr(scanner.socket.AF_INET, "192.168.1.111"),
            FakeAddr(scanner.socket.AF_INET6, "fe80::9870:ef43:6f95:ec98%wlp192s0"),
            FakeAddr(scanner.psutil.AF_LINK, "f4:28:9d:05:18:49"),
        ],
    }
    monkeypatch.setattr(scanner.psutil, "net_if_addrs", lambda: fake_addrs)

    result = scanner._detect_local_interfaces()

    assert result == [
        ("lo", None, ["127.0.0.1"]),
        ("wlp192s0", "f4:28:9d:05:18:49", ["192.168.1.111"]),
    ]


def test_detect_local_interfaces_drops_an_interface_with_neither_mac_nor_ipv4(monkeypatch):
    """Verify that _detect_local_interfaces omits an interface that has no real
    MAC and no IPv4 address at all - nothing a Network Interfaces row could
    usefully show, e.g. an IPv6-only tunnel interface."""
    class FakeAddr:
        def __init__(self, family, address):
            self.family = family
            self.address = address

    fake_addrs = {"tun0": [FakeAddr(scanner.socket.AF_INET6, "fe80::1")]}
    monkeypatch.setattr(scanner.psutil, "net_if_addrs", lambda: fake_addrs)

    result = scanner._detect_local_interfaces()

    assert result == []


def test_detect_local_network_excludes_0_0_0_0(monkeypatch):
    """Verify that _detect_local_network excludes 0.0.0.0 even if some interface
    reports it - psutil.net_if_addrs() doesn't normally do this (it reports
    addresses actually bound to an interface, not wildcard bind addresses), but a
    misconfigured or transitional interface on some system could. 0.0.0.0 isn't a
    genuine, connectable identity of this machine the way 127.0.0.1 or a real LAN
    address is, so it shouldn't be treated as one."""
    class FakeAddr:
        def __init__(self, family, address):
            self.family = family
            self.address = address

    fake_addrs = {
        "lo": [FakeAddr(scanner.socket.AF_INET, "127.0.0.1")],
        "eth0": [FakeAddr(scanner.socket.AF_INET, "0.0.0.0")],
        "wlan0": [FakeAddr(scanner.socket.AF_INET, "192.168.1.50")],
    }
    monkeypatch.setattr(scanner.psutil, "net_if_addrs", lambda: fake_addrs)

    local_ips, _ = scanner._detect_local_network()

    assert "0.0.0.0" not in local_ips
    assert local_ips == {"127.0.0.1", "192.168.1.50"}


async def test_ensure_probed_records_each_ip_as_probed_only_once(net_scanner):
    """Verify that _ensure_probed records each IP as probed only once no matter how
    many times it's called, by calling it twice for the same IP and once for a
    different one and checking the resulting probed set directly."""
    await net_scanner._ensure_probed("192.168.1.50")
    await net_scanner._ensure_probed("192.168.1.50")
    await net_scanner._ensure_probed("192.168.1.51")

    assert net_scanner.probed == {"192.168.1.50", "192.168.1.51"}


async def test_discover_mdns_service_builds_a_device_from_a_service_announcement(net_scanner, fake_zeroconf):
    """Verify that discover_mdns_service turns a live mDNS announcement into a
    Device carrying the right service, by feeding it a minimal fake zeroconf info
    object and checking the resulting state."""
    zc = fake_zeroconf(addresses=["10.0.0.9"])

    await net_scanner.discover_mdns_service(zc, "_smb._tcp.local.", "MyNAS._smb._tcp.local.")

    device = net_scanner.devices["10.0.0.9"]
    assert device.hostname == "MyNAS"
    assert "smb" in device.services
    assert device.found_by == {"mdns"}


async def test_discover_mdns_service_ignores_an_announcement_with_no_resolvable_address(net_scanner, fake_zeroconf):
    """Verify that discover_mdns_service does nothing when zeroconf can't resolve an
    address for the service, by feeding it an info object with an empty address
    list."""
    zc = fake_zeroconf(addresses=[])

    await net_scanner.discover_mdns_service(zc, "_smb._tcp.local.", "MyNAS._smb._tcp.local.")

    assert net_scanner.devices == {}


async def test_discover_mdns_service_canonicalizes_a_local_machine_ip(net_scanner, fake_zeroconf):
    """Verify that discover_mdns_service folds an mDNS announcement resolving to a
    known local-machine address into the canonical one too - this machine
    advertising a service of its own over mDNS shouldn't spawn a second, separate
    device entry any more than queue_probe finding it via /etc/hosts should."""
    zc = fake_zeroconf(addresses=["127.0.0.1"])

    await net_scanner.discover_mdns_service(zc, "_smb._tcp.local.", "MyNAS._smb._tcp.local.")

    assert "127.0.0.1" not in net_scanner.devices
    assert "smb" in net_scanner.devices["192.168.99.1"].services


async def test_request_items_skips_a_service_already_loading(net_scanner):
    """Verify that request_items doesn't run a fetch for a service that's already
    loading, by checking a FetchRecordingService that starts out loading=True never
    has its fetch() invoked."""
    service = FetchRecordingService(loading=True)

    await net_scanner.request_items(service)

    assert service.fetch_calls == []


async def test_request_items_runs_the_fetch_with_the_given_kwargs(net_scanner):
    """Verify that request_items runs the service's fetch() with the kwargs it was
    called with, by checking what a FetchRecordingService recorded."""
    service = FetchRecordingService()

    await net_scanner.request_items(service, user="bob")
    await net_scanner.wait_idle()

    assert service.fetch_calls == [{"user": "bob"}]


async def test_request_items_sets_loading_before_the_fetch_actually_runs(net_scanner):
    """Verify that request_items flips loading on *before* the fetch runs (not
    after), so a concurrent request during a slow fetch correctly no-ops, by
    checking what loading looked like at the moment a FetchRecordingService's fetch()
    was invoked."""
    service = FetchRecordingService()

    await net_scanner.request_items(service)
    await net_scanner.wait_idle()

    assert service.loading_during_fetch == [True]


async def test_ensure_fetched_triggers_a_fetch_for_a_not_yet_fetched_service(net_scanner):
    """Verify that ensure_fetched triggers a real fetch (via request_items) for a
    Fetchable service whose fetch_state is NOT_FETCHED."""
    service = FakeFetchable(fetch_state=FetchState.NOT_FETCHED)

    await net_scanner.ensure_fetched(service)
    await net_scanner.wait_idle()

    assert service.fetch_calls == [{}]


@pytest.mark.parametrize("fetch_state", [FetchState.LOADING, FetchState.LOADED, FetchState.AUTH_REQUIRED])
async def test_ensure_fetched_is_a_noop_once_a_fetch_has_already_been_attempted(net_scanner, fetch_state):
    """Verify that ensure_fetched does nothing for any fetch_state other than
    NOT_FETCHED, by checking no fetch is triggered across every other state -
    including AUTH_REQUIRED, which needs an explicit credentialed retry via
    request_items instead (see submit_login in ui/base.py), not another automatic
    anonymous attempt."""
    service = FakeFetchable(fetch_state=fetch_state)

    await net_scanner.ensure_fetched(service)
    await net_scanner.wait_idle()

    assert service.fetch_calls == []


async def test_ensure_fetched_is_a_noop_for_a_service_that_isnt_fetchable(net_scanner):
    """Verify that ensure_fetched does nothing for a service that doesn't implement
    Fetchable at all (e.g. Ssh, Ipp - services with no fetch() of their own), by
    checking a plain FetchRecordingService is left untouched rather than raising
    on a missing fetch_state."""
    service = FetchRecordingService()

    await net_scanner.ensure_fetched(service)

    assert service.fetch_calls == []


async def test_ensure_dns_resolved_triggers_a_reverse_lookup_for_an_unresolved_device(net_scanner, monkeypatch):
    """Verify that ensure_dns_resolved triggers a real reverse-DNS lookup (via
    _resolve_dns) for a device whose dns_resolved is still False, populating
    dns_hostname and marking the scanner dirty once it lands. Restores the real
    _resolve_reverse_hostname (conftest's autouse _no_real_dns_lookups stubs it
    out by default for every other test) since this one wants the genuine
    end-to-end chain down to socket.gethostbyaddr."""
    monkeypatch.setattr(scanner, "_resolve_reverse_hostname", discovery._resolve_reverse_hostname)
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("alpaca", [], [ip]))
    device = Device(hostname="192.168.1.253", ip="192.168.1.253")

    await net_scanner.ensure_dns_resolved(device)
    await net_scanner.wait_idle()

    assert device.dns_hostname == "alpaca"
    assert net_scanner.dirty is True


async def test_ensure_dns_resolved_is_a_noop_once_a_lookup_has_already_been_attempted(net_scanner, monkeypatch):
    """Verify that ensure_dns_resolved does nothing for a device whose
    dns_resolved is already True - a second row-expand shouldn't repeat the
    lookup, same as ensure_fetched not repeating a fetch."""
    calls = []

    async def fake_resolve(ip):
        calls.append(ip)
        return "alpaca"

    monkeypatch.setattr(scanner, "_resolve_reverse_hostname", fake_resolve)
    device = Device(hostname="192.168.1.253", ip="192.168.1.253", dns_resolved=True)

    await net_scanner.ensure_dns_resolved(device)
    await net_scanner.wait_idle()

    assert calls == []
    assert device.dns_hostname is None


@pytest.mark.parametrize("banner, expected", [
    (b"SSH-2.0-OpenSSH_9.6\r\n", True),
    (b"HTTP/1.1 200 OK\r\n", False),
])
async def test_verify_ssh_checks_for_the_ssh_version_banner(tcp_banner_server, banner, expected):
    """Verify that _verify_ssh only accepts a connection whose first bytes are a real
    SSH version banner, by running a local TCP server that sends either a real
    banner or unrelated bytes."""
    port = await tcp_banner_server(banner)

    result = await scanner._verify_ssh("127.0.0.1", port)

    assert result is expected


@pytest.mark.parametrize("banner, expected", [
    (b"RFB 003.008\n", True),
    (b"SSH-2.0-OpenSSH_9.6\r\n", False),
])
async def test_verify_vnc_checks_for_the_rfb_version_banner(tcp_banner_server, banner, expected):
    """Verify that _verify_vnc only accepts a connection whose first bytes are the
    RFB protocol version banner, by running a local TCP server that sends either a
    real RFB banner or unrelated bytes."""
    port = await tcp_banner_server(banner)

    result = await scanner._verify_vnc("127.0.0.1", port)

    assert result is expected


async def test_verify_ssh_fails_closed_when_nothing_is_listening():
    """Verify that _verify_ssh returns False rather than raising when nothing is
    listening on the target port, by probing an almost-certainly-unused port."""
    result = await scanner._verify_ssh("127.0.0.1", 1)

    assert result is False


async def test_verify_cups_checks_the_server_header(fake_http_connection):
    """Verify that _verify_cups accepts a response whose Server header names CUPS,
    by faking the HTTP layer with a matching header."""
    fake_http_connection(headers={"Server": "CUPS/2.4 IPP/2.1"})

    result = await scanner._verify_cups("10.0.0.5", 631)

    assert result is True


@pytest.mark.parametrize("payload, expected", [
    ({"metadata": {"api_extensions": []}}, True),
    ({"metadata": {"unrelated": True}}, False),
])
async def test_verify_incus_requires_the_api_extensions_field(fake_http_connection, payload, expected):
    """Verify that _verify_incus checks for the api_extensions field in the /1.0
    metadata rather than accepting any JSON body, by faking the HTTP layer (the
    true external edge incus_get itself calls out to) with matching and generic
    response bodies - exercising incus_get's own request/JSON-parsing logic too."""
    fake_http_connection(body=json.dumps(payload).encode())

    result = await scanner._verify_incus("10.0.0.5", 8443)

    assert result is expected
