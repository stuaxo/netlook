"""Reusable test doubles - lightweight stand-ins for collaborators that only need to
record what they were called with, with no fixture lifecycle (no monkeypatching, no
teardown) of their own. See conftest.py for fixtures that do need that.
"""
from netlook.core.models import Fetchable, FetchState


class FakeScanner:
    """Records request_items calls instead of touching the real async core - used
    wherever a test drives Service.resources()/Action.run()'s scanner hand-off.
    ensure_fetched mirrors NetworkScanner's own gating logic (not a dumb stub) so
    tests exercising build_device_row_view get the real "only fetch if
    NOT_FETCHED" behavior instead of a fake that always/never triggers."""

    def __init__(self):
        self.requested = []
        self.dns_resolved = []

    async def request_items(self, service, **kwargs):
        self.requested.append((service, kwargs))

    async def ensure_fetched(self, service):
        if isinstance(service, Fetchable) and service.fetch_state == FetchState.NOT_FETCHED:
            await self.request_items(service)

    async def ensure_dns_resolved(self, dev):
        self.dns_resolved.append(dev)


class FetchRecordingService:
    """A minimal stand-in for the Service.fetch() contract that
    NetworkScanner.request_items() depends on: tracks whether/how many times fetch()
    ran, what it was called with, and what `loading` looked like at the moment it
    ran (to verify ordering guarantees, e.g. loading flips on before fetch starts)."""

    def __init__(self, loading: bool = False):
        self.loading = loading
        self.fetch_calls = []
        self.loading_during_fetch = []

    async def fetch(self, **kwargs):
        self.loading_during_fetch.append(self.loading)
        self.fetch_calls.append(kwargs)


class FakeFetchable(Fetchable):
    """A minimal Fetchable double whose fetch_state is set directly rather than
    derived from real service fields - used by NetworkScanner.ensure_fetched
    tests, which need to control fetch_state independently of any one real
    Service subclass's own state-derivation logic (already covered by
    Samba/Incus/Cups's own fetch_state tests in test_services.py)."""

    def __init__(self, fetch_state: FetchState, loading: bool = False):
        self._fetch_state = fetch_state
        self.loading = loading
        self.fetch_calls = []

    @property
    def fetch_state(self) -> FetchState:
        return self._fetch_state

    async def fetch(self, **kwargs):
        self.fetch_calls.append(kwargs)
