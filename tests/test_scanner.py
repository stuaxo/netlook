"""Unit tests for netlook.core.scanner."""
import json

import pytest

from netlook.core import scanner
from netlook.core.scanner import _parse_ports, _split_addresses

from doubles import FetchRecordingService


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


async def test_start_seeds_the_local_machine_device_with_localhost_as_a_name(net_scanner):
    """Verify that start() pre-seeds the canonical local-machine device with
    "localhost" as its hostname and one of its names, so this machine shows up in
    the browser - recognizable as itself - even before any discovery engine or
    probe reports anything about it."""
    await net_scanner.start()

    device = net_scanner.devices["192.168.99.1"]
    assert device.hostname == "localhost"
    assert device.names["localhost"] == {"localhost"}


async def test_start_attaches_physical_interfaces_to_the_local_machine_device():
    """Verify that start() attaches local_physical_interfaces to the seeded
    local-machine device, so a machine with a real network interface shows a
    Physical Devices section in its own Properties tab."""
    net_scanner = scanner.NetworkScanner(
        discovery_engines=[],
        local_network=({"127.0.0.1", "192.168.99.1"}, "192.168.99.1"),
        local_physical_interfaces=[("wlan0", "aa:bb:cc:dd:ee:ff")],
    )

    async def no_probe(ip, connect_ips=None):
        pass

    net_scanner._probe = no_probe
    await net_scanner.start()

    assert net_scanner.devices["192.168.99.1"].physical_interfaces == [("wlan0", "aa:bb:cc:dd:ee:ff")]
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


def test_detect_local_physical_interfaces_excludes_the_null_mac(monkeypatch):
    """Verify that _detect_local_physical_interfaces skips the all-zero MAC every
    OS reports for loopback - it's a virtual interface, not a physical device, so
    it shouldn't count toward whether the Physical Devices section has anything to
    show. A real interface's MAC is kept."""
    class FakeAddr:
        def __init__(self, family, address):
            self.family = family
            self.address = address

    fake_addrs = {
        "lo": [FakeAddr(scanner.psutil.AF_LINK, "00:00:00:00:00:00")],
        "wlan0": [FakeAddr(scanner.psutil.AF_LINK, "aa:bb:cc:dd:ee:ff")],
    }
    monkeypatch.setattr(scanner.psutil, "net_if_addrs", lambda: fake_addrs)

    result = scanner._detect_local_physical_interfaces()

    assert result == [("wlan0", "aa:bb:cc:dd:ee:ff")]


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
