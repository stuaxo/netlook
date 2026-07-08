"""Reusable test doubles - lightweight stand-ins for collaborators that only need to
record what they were called with, with no fixture lifecycle (no monkeypatching, no
teardown) of their own. See conftest.py for fixtures that do need that.
"""


class FakeScanner:
    """Records request_items calls instead of touching the real async core - used
    wherever a test drives Service.get_resources()/Action.run()'s scanner hand-off."""

    def __init__(self):
        self.requested = []

    async def request_items(self, service, **kwargs):
        self.requested.append((service, kwargs))


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
