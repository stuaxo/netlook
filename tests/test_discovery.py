"""Unit tests for netlook.core.discovery."""
import socket

import httpx
import pytest

from netlook.core import discovery
from netlook.core.discovery import (
    WsdDiscovery,
    _fetch_wsd_friendly_name,
    _is_local,
    _parse_etc_hosts,
    _parse_known_hosts,
    _pick_address,
)


@pytest.mark.parametrize("addr, expected", [
    ("192.168.1.5", True),
    ("10.0.0.1", True),
    ("169.254.1.1", True),  # link-local counts as local for this purpose
    ("8.8.8.8", False),
    ("not-an-ip", False),
])
def test_is_local_accepts_private_and_link_local_addresses(addr, expected):
    """Verify that _is_local accepts RFC1918/link-local addresses and rejects public
    IPs and non-IP strings, by checking one representative address per category."""
    result = _is_local(addr)

    assert result is expected


def test_parse_etc_hosts_yields_one_pair_per_alias_and_skips_loopback_and_public(tmp_path):
    """Verify that _parse_etc_hosts yields (ip, alias) pairs for every alias on a
    local line while skipping loopback and public-IP lines entirely, by parsing a
    realistic /etc/hosts fixture."""
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "127.0.0.1\tlocalhost\n"
        "::1\t\tlocalhost ip6-localhost\n"
        "192.168.1.10\tnas.local nas\n"
        "8.8.8.8\t\tsome-public-thing\n"
        "# a comment line\n"
        "10.0.0.5\tdev-box   # trailing comment\n"
    )

    entries = list(_parse_etc_hosts(hosts_file))

    assert entries == [
        ("192.168.1.10", "nas.local"),
        ("192.168.1.10", "nas"),
        ("10.0.0.5", "dev-box"),
    ]


def test_parse_etc_hosts_yields_nothing_for_a_missing_file(tmp_path):
    """Verify that _parse_etc_hosts fails gracefully with no entries and no
    exception when the file doesn't exist, by pointing it at a path never created."""
    entries = list(_parse_etc_hosts(tmp_path / "does-not-exist"))

    assert entries == []


async def test_parse_known_hosts_skips_hashed_lines_and_resolves_local_entries(tmp_path, monkeypatch):
    """Verify that _parse_known_hosts skips hashed entries, resolves .local
    hostnames, keeps plain local IPs, drops public IPs, and handles comma-separated
    and [host]:port forms, by parsing a realistic known_hosts fixture."""
    def fake_resolve(name):
        if name in ("myhost.local", "host2.local"):
            return "192.168.1.15"
        raise OSError("no resolver")

    monkeypatch.setattr(socket, "gethostbyname", fake_resolve)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "myhost.local ssh-rsa AAAAB3NzaC1yc2EAAAA\n"
        "192.168.1.99 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n"
        "8.8.8.8 ssh-rsa AAAAB3NzaC1yc2EAAAA\n"
        "|1|hashedstuff|hashedstuff2= ssh-rsa AAAAB3NzaC1yc2EAAAA\n"
        "host1,host2.local,192.168.1.30 ssh-rsa AAAAB3NzaC1yc2EAAAA\n"
        "[myhost.local]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAA\n"
    )

    entries = [entry async for entry in _parse_known_hosts(known_hosts)]

    assert ("192.168.1.15", "myhost.local") in entries
    assert ("192.168.1.99", None) in entries
    assert not any(ip == "8.8.8.8" for ip, _ in entries)
    assert not any(name == "hashedstuff" for _, name in entries)
    assert ("192.168.1.15", "host2.local") in entries
    assert ("192.168.1.30", None) in entries


@pytest.mark.parametrize("xaddrs, expected", [
    (
        ["http://[fe80::1a2b:3c4d:5e6f:7a8b]:5357/abc", "http://192.168.1.144:5357/abc"],
        ("192.168.1.144", "http://192.168.1.144:5357/abc"),
    ),
    (["http://[fe80::1a2b:3c4d:5e6f:7a8b]:5357/abc"], None),
    (["http://[2001:db8::1]:5357/abc"], ("2001:db8::1", "http://[2001:db8::1]:5357/abc")),
    (
        ["http://[2001:db8::1]:5357/abc", "http://192.168.1.144:5357/abc"],
        ("192.168.1.144", "http://192.168.1.144:5357/abc"),
    ),
], ids=[
    "link-local-and-ipv4-prefers-ipv4",
    "link-local-only-yields-nothing",
    "global-ipv6-only-is-used",
    "global-ipv6-and-ipv4-prefers-ipv4",
])
async def test_pick_address_prefers_ipv4_and_skips_link_local(xaddrs, expected):
    """Verify that _pick_address chooses one representative address per WSD service
    - preferring IPv4, skipping link-local entirely, and falling back to a routable
    IPv6 address if that's all there is - by checking several XAddr mixes."""
    result = await _pick_address(xaddrs)

    assert result == expected


async def test_pick_address_resolves_a_bare_hostname_xaddr(monkeypatch):
    """Verify that _pick_address resolves a hostname-only XAddr (some WSD
    responders, e.g. Samba's wsdd, advertise their bare hostname instead of an IP)
    to a real address rather than returning the hostname string itself - a device
    keyed by a hostname instead of its actual IP could never merge with the same
    physical host discovered via another engine (mDNS/smb reporting it by IP)."""
    def fake_resolve(name):
        if name == "werner":
            return "192.168.1.80"
        raise OSError("no resolver")

    monkeypatch.setattr(socket, "gethostbyname", fake_resolve)

    result = await _pick_address(["http://werner:5357/abc"])

    assert result == ("192.168.1.80", "http://werner:5357/abc")


async def test_pick_address_prefers_an_ip_literal_over_a_resolvable_hostname(monkeypatch):
    """Verify that a hostname-only XAddr is only used as a last resort - an
    IP-literal XAddr in the same list always wins, even though it's checked first
    and would otherwise short-circuit before the hostname is ever resolved."""
    monkeypatch.setattr(socket, "gethostbyname", lambda name: "192.168.1.80")

    result = await _pick_address(["http://werner:5357/abc", "http://192.168.1.144:5357/abc"])

    assert result == ("192.168.1.144", "http://192.168.1.144:5357/abc")


async def test_pick_address_drops_a_hostname_xaddr_that_fails_to_resolve(monkeypatch):
    """Verify that a hostname-only XAddr is dropped entirely (not queued with a
    broken, non-IP address) when it can't be resolved - e.g. no mDNS/WINS resolver
    configured for that name."""
    def fake_resolve(name):
        raise OSError("no resolver")

    monkeypatch.setattr(socket, "gethostbyname", fake_resolve)

    result = await _pick_address(["http://werner:5357/abc"])

    assert result is None


async def test_fetch_wsd_friendly_name_extracts_the_name_regardless_of_namespace_prefix(fake_http_connection):
    """Verify that _fetch_wsd_friendly_name extracts FriendlyName from a WS-Transfer
    response body regardless of its XML namespace prefix, by faking the HTTP layer
    with a realistic DPWS ThisDevice response."""
    body = b"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
  <soap:Body>
    <wsdp:ThisDevice>
      <wsdp:FriendlyName xml:lang="en-US">DESKTOP-ABC123</wsdp:FriendlyName>
    </wsdp:ThisDevice>
  </soap:Body>
</soap:Envelope>"""
    fake_http_connection(body=body)

    name = await _fetch_wsd_friendly_name("http://192.168.1.77:5357/abc")

    assert name == "DESKTOP-ABC123"


async def test_fetch_wsd_friendly_name_returns_none_when_the_endpoint_is_unreachable(monkeypatch):
    """Verify that _fetch_wsd_friendly_name fails gracefully (returns None, doesn't
    raise) when the metadata endpoint can't be reached, by monkeypatching the client
    to raise a connection error."""
    async def failing_post(self, *args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", failing_post)

    name = await _fetch_wsd_friendly_name("http://192.168.1.77:5357/abc")

    assert name is None


async def test_wsd_discovery_report_probes_exactly_one_address_per_service(monkeypatch):
    """Verify that WsdDiscovery._report calls queue_probe exactly once per service
    even when several XAddrs are advertised, by feeding a real wsdiscovery Service
    with both a link-local and a real address and checking only one call happens."""
    from wsdiscovery.service import Service as WsdService

    async def fake_fetch_name(xaddr):
        return None

    monkeypatch.setattr(discovery, "_fetch_wsd_friendly_name", fake_fetch_name)
    calls = []

    class FakeCtx:
        async def queue_probe(self, ip, hostname=None, source=""):
            calls.append((ip, hostname, source))

    svc = WsdService(
        types=[], scopes=[],
        xAddrs=["http://[fe80::1a2b:3c4d:5e6f:7a8b]:5357/abc", "http://192.168.1.144:5357/abc"],
        epr="urn:uuid:4509a320-00a0-8023-00b9-4509a320be6b",
        instanceId=0,
    )
    wsd = WsdDiscovery()
    wsd._scanner_ctx = FakeCtx()

    await wsd._report(svc)

    assert calls == [("192.168.1.144", "4509a320-00a0-8023-00b9-4509a320be6b", "WSD")]
