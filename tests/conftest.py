"""Shared pytest fixtures.

Tests in this suite follow Arrange/Act/Assert, separated by blank lines rather than
inline `# Arrange`/`# Act`/`# Assert` labels.
"""
import asyncio
import subprocess

import httpx
import pytest

from netlook.core.models import SERVICE_REGISTRY
from netlook.core.scanner import NetworkScanner


@pytest.fixture
def service_registry():
    """Yields the live, process-global SERVICE_REGISTRY for a test to freely mutate
    (e.g. via @register) and restores it to exactly its prior state afterwards, so
    throwaway registrations never leak into the rest of the suite."""
    original = dict(SERVICE_REGISTRY)
    yield SERVICE_REGISTRY
    SERVICE_REGISTRY.clear()
    SERVICE_REGISTRY.update(original)


@pytest.fixture
def empty_service_registry(service_registry):
    """Same restore-after guarantee as service_registry, but starts the test with a
    completely empty registry - useful for testing registry-dependent behavior (like
    make_service's fallback to the base Service) in isolation from whatever
    services.py has really registered."""
    service_registry.clear()
    yield service_registry


@pytest.fixture
async def tcp_banner_server():
    """Starts a background asyncio TCP server on 127.0.0.1 that sends a fixed banner
    to the first client that connects. Yields a factory: await it with the banner
    bytes to get back the bound port. Every server started is torn down
    automatically."""
    servers = []

    async def start(banner: bytes) -> int:
        async def serve(reader, writer):
            try:
                writer.write(banner)
                await writer.drain()
            finally:
                writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        servers.append(server)
        return server.sockets[0].getsockname()[1]

    yield start

    for server in servers:
        server.close()
        await server.wait_closed()


@pytest.fixture
def fake_http_connection(monkeypatch):
    """Replaces httpx.AsyncClient with one whose requests always resolve against a
    fixed in-memory response, regardless of the real request made against it. This is
    the true external-network edge every protocol verifier and Service.fetch()
    ultimately calls out to, so it's the right place to fake a server's response -
    rather than mocking our own request-building/parsing functions and skipping over
    them untested. Call it with the response body (and optional headers/status);
    unlike the old http.client-based version this needs no secure= flag - a
    MockTransport intercepts a request regardless of http:// vs https://."""
    def configure(body: bytes = b"", headers: dict | None = None, status_code: int = 200):
        def handler(request):
            return httpx.Response(status_code, headers=headers or {}, content=body)

        transport = httpx.MockTransport(handler)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = transport
            original_init(self, *args, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    return configure


@pytest.fixture
def fake_zeroconf():
    """A minimal AsyncZeroconf stand-in for discover_mdns_service tests. Call it
    with the addresses (and optional port/properties) async_get_service_info()
    should resolve to; pass no addresses to simulate an unresolvable service."""
    def build(addresses: list[str] = (), port: int = 445, properties: dict | None = None):
        class FakeInfo:
            def __init__(self):
                self.port = port
                self.properties = properties or {}

            def parsed_addresses(self):
                return list(addresses)

        class FakeZeroconf:
            async def async_get_service_info(self, type_, name):
                return FakeInfo()

        return FakeZeroconf()

    return build


@pytest.fixture
def popen_calls(monkeypatch):
    """Captures every subprocess.Popen call instead of actually launching an
    external process. This is the one genuine external-system edge Action.run()
    implementations touch (xdg-open, remmina) - a plain synchronous call even though
    run() itself is async - so it's the right, and only, place to fake in that code
    path."""
    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda cmd: calls.append(cmd))
    return calls


@pytest.fixture
async def net_scanner():
    """A NetworkScanner with no discovery engines and real network probing stubbed
    out, so tests never touch the network. local_network and
    local_physical_interfaces are likewise fixed, fake values (rather than the real
    _detect_local_network()/_detect_local_physical_interfaces(), which reflect
    whatever's actually present on the machine running the tests) - "192.168.99.1"
    is chosen to be well outside every IP any other test in this suite uses, so
    fixture-default local-machine canonicalization never accidentally kicks in for
    an unrelated test's device IP. local_physical_interfaces defaults to empty
    (rather than a fake interface) so tests aren't surprised by an unrequested
    Physical Devices section - tests that specifically want one pass their own."""
    net_scanner = NetworkScanner(
        discovery_engines=[],
        local_network=({"127.0.0.1", "192.168.99.1"}, "192.168.99.1"),
        local_physical_interfaces=[],
    )

    async def no_probe(ip, connect_ips=None):
        pass

    net_scanner._probe = no_probe
    yield net_scanner
    await net_scanner.close()
