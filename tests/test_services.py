"""Unit tests for netlook.core.services."""
import json

import pytest

from netlook.core import services
from netlook.core.actions import CredentialAction, ShareAction, SmbPrinterAction, WebAdminAction
from netlook.core.services import Cups, DeviceInfo, Incus, Ipp, LpdPrinterService, PdlStreamService, Samba

from doubles import FakeScanner
from factories import DeviceFactory


@pytest.fixture
def fake_smbclient(monkeypatch):
    """Stands in for the real `smbclient` binary that list_smb_shares() shells out
    to - the actual external-process boundary - so Samba.fetch can be exercised
    through its real parsing logic without spawning a real smbclient. Call it with
    the grepable stdout `smbclient -L -g` would produce (and optionally a
    returncode)."""
    monkeypatch.setattr(services, "HAS_SMBCLIENT", True)

    def configure(stdout: str = "", returncode: int = 0):
        class FakeProcess:
            def __init__(self):
                self.returncode = returncode

            async def communicate(self):
                return stdout.encode(), b""

        async def fake_create_subprocess_exec(*cmd, **kwargs):
            return FakeProcess()

        monkeypatch.setattr(services.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    return configure


@pytest.mark.parametrize("service_cls", [PdlStreamService, LpdPrinterService])
async def test_silent_printer_services_never_yield_resources(service_cls):
    """Verify that PdlStreamService and LpdPrinterService yield no resources in
    either state, since they're machine-to-machine protocols with nothing to click,
    by checking both expanded=False and expanded=True come back empty."""
    service = service_cls(kind="pdl-datastream", ip="10.0.0.20", port=9100)

    collapsed = [r async for r in service.get_resources(expanded=False, scanner=None)]
    expanded = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert collapsed == []
    assert expanded == []


async def test_samba_get_resources_requests_a_fetch_on_first_expand():
    """Verify that expanding a freshly-discovered Samba service (no fetch yet)
    requests items from the scanner instead of yielding resources, by checking the
    fake scanner recorded exactly one anonymous request_items call."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    scanner = FakeScanner()

    yielded = [r async for r in service.get_resources(expanded=True, scanner=scanner)]

    assert yielded == []
    assert scanner.requested == [(service, {})]


async def test_samba_get_resources_prompts_for_credentials_after_a_failed_anonymous_fetch():
    """Verify that a failed anonymous fetch surfaces a CredentialAction instead of
    re-triggering another anonymous fetch, by simulating that post-fetch state
    directly. This is a regression test: auth_required used to be checked *after*
    "shares is None", which looped forever re-requesting an anonymous fetch."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = None
    service.auth_required = True
    scanner = FakeScanner()

    yielded = [r async for r in service.get_resources(expanded=True, scanner=scanner)]

    assert len(yielded) == 1
    assert isinstance(yielded[0].action, CredentialAction)
    assert scanner.requested == []


def test_samba_status_text_reports_loading_regardless_of_other_state():
    """Verify that Samba.status_text reports "loading..." whenever loading is set,
    by checking it wins over an otherwise-conflicting "shares is None" state."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445, loading=True)

    assert service.status_text == "loading..."


def test_samba_status_text_reports_no_shares_found_only_for_a_genuinely_empty_fetch():
    """Verify that Samba.status_text reports "no shares found" only once a fetch
    succeeded with zero shares, by setting shares=[] with auth_required False."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = []

    assert service.status_text == "no shares found"


async def test_samba_fetch_records_a_successful_anonymous_listing(fake_smbclient):
    """Verify that Samba.fetch stores the shares parsed from a real smbclient-style
    grepable listing and clears auth_required, by configuring the process-boundary
    fixture with a successful output - exercising list_smb_shares's own parsing too."""
    fake_smbclient(stdout="Disk|Public|\nDisk|Media|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445, loading=True)

    await service.fetch()

    assert service.loading is False
    assert service.shares == ["Public", "Media"]
    assert service.auth_required is False


async def test_samba_fetch_flags_tried_auth_only_for_a_failed_credentialed_attempt(fake_smbclient):
    """Verify that Samba.fetch sets tried_auth only when a *credentialed* attempt
    fails (not an anonymous one), by configuring a nonzero-exit/empty-output failure
    for both and comparing the two outcomes."""
    fake_smbclient(stdout="", returncode=1)
    anonymous = Samba(kind="smb", ip="10.0.0.5", port=445)
    credentialed = Samba(kind="smb", ip="10.0.0.5", port=445)

    await anonymous.fetch()
    await credentialed.fetch(user="bob", password="secret")

    assert anonymous.tried_auth is False
    assert credentialed.tried_auth is True


async def test_list_smb_shares_parses_both_disk_and_printer_lines(fake_smbclient):
    """Verify that list_smb_shares splits smbclient's grepable output into separate
    disk-share and printer-share lists, by configuring a listing with one of each."""
    fake_smbclient(stdout="Disk|Public|\nPrinter|OfficeLaser|\nDisk|Media|\n")

    shares, printers = await services.list_smb_shares("10.0.0.5")

    assert shares == ["Public", "Media"]
    assert printers == ["OfficeLaser"]


async def test_samba_fetch_stores_both_shares_and_printers(fake_smbclient):
    """Verify that Samba.fetch stores both lists from a mixed listing, by checking
    both fields land on the service after a fetch that includes a printer share."""
    fake_smbclient(stdout="Disk|Public|\nPrinter|OfficeLaser|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    await service.fetch()

    assert service.shares == ["Public"]
    assert service.printers == ["OfficeLaser"]


async def test_samba_get_resources_yields_both_shares_and_printers_together():
    """Verify that Samba.get_resources yields both disk shares and printer shares
    together - smb is single-category (see SERVICE_CATEGORIES's comment: both
    share types come from the same fetch and belong in the same File Shares tab,
    rather than splitting printer shares into their own dedicated tab that would be
    a dead label whenever there are none)."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = ["Public"]
    service.printers = ["OfficeLaser"]

    yielded = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert {type(r.action) for r in yielded} == {ShareAction, SmbPrinterAction}


async def test_samba_get_resources_yields_credential_prompt_once_auth_required():
    """Verify that Samba.get_resources surfaces a CredentialAction once auth is
    required, rather than the share/printer lists."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = None
    service.auth_required = True

    resources = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert len(resources) == 1
    assert isinstance(resources[0].action, CredentialAction)


async def test_incus_get_resources_always_yields_web_admin_when_collapsed():
    """Verify that Incus.get_resources yields a web-admin resource when collapsed
    regardless of instance-fetch state, by checking a freshly-created service with
    no fetch yet still yields exactly one WebAdminAction pointing at the UI root."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)

    yielded = [r async for r in service.get_resources(expanded=False, scanner=None)]

    assert len(yielded) == 1
    assert isinstance(yielded[0].action, WebAdminAction)
    assert yielded[0].action.uri == "https://10.0.0.5:8443/ui/"


async def test_incus_get_resources_requests_a_fetch_on_first_expand():
    """Verify that expanding an Incus service with no instances fetched yet still
    yields the general web-admin link (so the tab is never a dead end while
    instances are loading) and requests items, by checking the fake scanner
    recorded it."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)
    scanner = FakeScanner()

    yielded = [r async for r in service.get_resources(expanded=True, scanner=scanner)]

    assert [r.action.label for r in yielded] == ["Incus admin"]
    assert scanner.requested == [(service, {})]


async def test_incus_get_resources_yields_one_console_action_per_instance():
    """Verify that Incus.get_resources yields the general web-admin link plus an
    IncusConsoleAction per fetched instance once populated, by setting instances
    directly and expanding - the general link supplements per-instance links
    rather than being replaced by them, so there's always something to click even
    if the instance list turns out to be empty."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)
    service.instances = [{"name": "web", "status": "Running"}, {"name": "db", "status": "Stopped"}]

    yielded = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert [r.action.label for r in yielded] == ["Incus admin", "web (Running)", "db (Stopped)"]


async def test_incus_fetch_marks_inaccessible_on_a_forbidden_or_malformed_response(fake_http_connection):
    """Verify that Incus.fetch treats a non-200 or malformed payload as "not
    accessible" rather than "zero instances", by faking the HTTP layer (the true
    external edge incus_get calls out to) with a forbidden-shaped response - the
    real shape incus/LXD sends for an untrusted TLS client cert, confirmed live
    against a real server."""
    payload = {"type": "error", "status_code": 0, "error_code": 403, "error": "not authorized", "metadata": None}
    fake_http_connection(body=json.dumps(payload).encode())
    service = Incus(kind="incus", ip="10.0.0.5", port=8443, loading=True)

    await service.fetch()

    assert service.loading is False
    assert service.accessible is False
    assert service.instances == []
    assert service.status_text == "not accessible"
    assert service.error == "not authorized"
    assert service.extra_properties() == [("error", "not authorized")]


async def test_incus_fetch_records_a_generic_error_when_the_response_has_none(fake_http_connection):
    """Verify that Incus.fetch falls back to a generic "unexpected response"
    message when a non-200/malformed payload has no "error" field of its own to
    surface - still something more useful in Properties than silence."""
    fake_http_connection(body=json.dumps({"status_code": 403}).encode())
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)

    await service.fetch()

    assert service.error == "unexpected response"


async def test_incus_fetch_records_no_response_when_the_connection_fails(fake_http_connection):
    """Verify that Incus.fetch records "no response" specifically when incus_get
    itself returned None (connection failed, or the body wasn't valid JSON) -
    distinct wording from a response that came back but without an error field."""
    fake_http_connection(body=b"not valid json")
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)

    await service.fetch()

    assert service.error == "no response"


async def test_incus_fetch_records_instances_from_a_successful_payload(fake_http_connection):
    """Verify that Incus.fetch extracts name/status pairs from a successful
    recursive instance listing, by faking the HTTP layer with a realistic payload
    body - exercising incus_get's own request/JSON-parsing logic too."""
    payload = {
        "status_code": 200,
        "metadata": [{"name": "web", "status": "Running"}, {"name": "db", "status": "Stopped"}],
    }
    fake_http_connection(body=json.dumps(payload).encode())
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)

    await service.fetch()

    assert service.accessible is True
    assert service.instances == [{"name": "web", "status": "Running"}, {"name": "db", "status": "Stopped"}]
    assert service.error is None
    assert service.extra_properties() == []


async def test_incus_fetch_clears_a_stale_error_once_accessible_again(fake_http_connection):
    """Verify that a previously-recorded error is cleared once a later fetch
    succeeds - e.g. after the user trusts the client cert - rather than lingering
    in Properties describing a problem that's already been fixed."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443, error="not authorized", accessible=False)
    payload = {"status_code": 200, "metadata": []}
    fake_http_connection(body=json.dumps(payload).encode())

    await service.fetch()

    assert service.error is None
    assert service.extra_properties() == []


@pytest.mark.parametrize("html, expected_queues", [
    (b'<a href="/printers/OfficeLaser">OfficeLaser</a>', ["OfficeLaser"]),
    (b'<A HREF="/printers/Reception">x</A> <A HREF="/printers/Reception">dup</A>', ["Reception"]),
    (b"<html><body>no queues here</body></html>", []),
], ids=["lowercase-href", "uppercase-href-deduplicates-repeat", "no-queues-found"])
async def test_cups_fetch_scrapes_deduplicated_queue_names_from_the_printers_page(
    fake_http_connection, html, expected_queues,
):
    """Verify that Cups.fetch extracts and deduplicates queue names from the HTML
    /printers/ page regardless of href attribute casing, by faking the HTTP layer
    with a canned response body."""
    fake_http_connection(body=html)
    service = Cups(kind="cups", ip="10.0.0.40", port=631, loading=True)

    await service.fetch()

    assert service.loading is False
    assert service.queues == expected_queues


async def test_cups_get_resources_targets_the_specific_queue_sub_path():
    """Verify that Cups.get_resources builds a per-queue WebAdminAction pointing at
    /printers/{queue}, alongside the general web-admin link (see Incus's
    equivalent test for why that's not replaced), by expanding a service with
    queues already populated."""
    service = Cups(kind="cups", ip="10.0.0.40", port=631)
    service.queues = ["Laser1"]

    yielded = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert len(yielded) == 2
    assert yielded[-1].action.uri == "http://10.0.0.40:631/printers/Laser1"


async def test_ipp_get_resources_prefers_the_advertised_adminurl():
    """Verify that Ipp.get_resources uses the adminurl txt record verbatim when
    present instead of guessing a port-80 fallback, by checking the built action's
    uri matches the txt record exactly."""
    service = Ipp(kind="ipp", ip="10.0.0.30", port=631,
                  properties={b"adminurl": b"http://10.0.0.30/hp/device/index.html"})

    yielded = [r async for r in service.get_resources(expanded=False, scanner=None)]

    assert yielded[0].action.uri == "http://10.0.0.30/hp/device/index.html"


async def test_ipp_get_resources_falls_back_to_port_80_without_an_adminurl():
    """Verify that Ipp.get_resources falls back to port 80 on the service's own IP
    when no adminurl txt record is present, by checking the built action's uri."""
    service = Ipp(kind="ipp", ip="10.0.0.31", port=631, properties={})

    yielded = [r async for r in service.get_resources(expanded=False, scanner=None)]

    assert yielded[0].action.uri == "http://10.0.0.31:80/"


async def test_ipp_get_resources_yields_the_same_resource_regardless_of_expanded():
    """Verify that Ipp.get_resources ignores expanded and yields the same admin-page
    resource either way. ipp has no deeper, per-resource content to reveal once
    expanded (unlike smb/incus/cups), so its Printers tab must keep showing the same
    resource Overview does - a dead, actionless tab would be a regression for a
    service that plainly has one resource available. Regression test: this used to
    return nothing once expanded=True, leaving a dead label in the Printers tab."""
    service = Ipp(kind="ipp", ip="10.0.0.31", port=631, properties={})

    collapsed = [r async for r in service.get_resources(expanded=False, scanner=None)]
    expanded = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert len(expanded) == 1
    assert expanded[0].action.uri == collapsed[0].action.uri


def test_ipp_enrich_device_adds_ty_and_note_as_aliases_not_primary():
    """Verify that Ipp.enrich_device offers the "ty"/"note" txt records as aliases
    rather than promoting them over a name someone deliberately gave the device, by
    checking hostname stays the instance name while both extra fields land as
    aliases."""
    device = DeviceFactory(hostname="Printer3")
    service = Ipp(kind="ipp", ip="10.0.0.32", port=631, discovered_name="Printer3",
                  properties={b"ty": b"HP LaserJet Pro M404dn", b"note": b"2nd Floor"})

    service.enrich_device(device)

    assert device.hostname == "Printer3"
    assert device.aliases == {"HP LaserJet Pro M404dn": {"ipp"}, "2nd Floor": {"ipp"}}


def test_device_info_enrich_device_promotes_the_instance_name_and_ignores_the_model_code():
    """Verify that DeviceInfo.enrich_device promotes the friendlier mDNS instance
    name to primary and never files the hardware model code as a name/alias at
    all - it's metadata, not something anyone would call the device by, and stays
    visible in the Properties tab's raw txt record dump regardless."""
    device = DeviceFactory(hostname="MyNAS", names={"MyNAS": {"smb"}})
    service = DeviceInfo(kind="device-info", ip="10.0.0.5", port=0,
                          discovered_name="Stuart's NAS", properties={b"model": b"Synology-DS920+"})

    service.enrich_device(device)

    assert device.hostname == "Stuart's NAS"
    assert device.aliases == {"MyNAS": {"smb"}}


def test_device_info_enrich_device_never_promotes_the_model_code_as_hostname():
    """Verify that DeviceInfo.enrich_device leaves hostname untouched when there's
    no mDNS instance name - falling back to a bare IP (whatever hostname the
    device already had) rather than a hardware model code, which used to be
    promoted here as a "better than nothing" name."""
    device = DeviceFactory(hostname="10.0.0.5")
    service = DeviceInfo(kind="device-info", ip="10.0.0.5", port=0,
                          discovered_name=None, properties={b"model": b"Synology-DS920+"})

    service.enrich_device(device)

    assert device.hostname == "10.0.0.5"


def test_device_info_enrich_device_sets_icon_path_when_advertised():
    """Verify that DeviceInfo.enrich_device stores the icon txt record on the
    device, by checking icon_path after enrichment."""
    device = DeviceFactory(hostname="seed")
    service = DeviceInfo(kind="device-info", ip="10.0.0.5", port=0,
                          discovered_name="seed", properties={b"icon": b"/tmp/icon.png"})

    service.enrich_device(device)

    assert device.icon_path == "/tmp/icon.png"
