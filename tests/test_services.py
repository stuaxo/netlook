"""Unit tests for netlook.core.services."""
import json

import pytest

from netlook.core import services
from netlook.core.actions import LaunchAction
from netlook.core.models import FetchState, ResourceCategory
from netlook.core.services import (
    Cups, DeviceInfo, Incus, IncusInstance, Ipp, LpdPrinterService, PdlStreamService, Samba, SmbShare, Ssh,
)

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
def test_silent_printer_services_never_yield_resources(service_cls):
    """Verify that PdlStreamService and LpdPrinterService yield no resources at
    all, since they're machine-to-machine protocols with nothing to click."""
    service = service_cls(kind="pdl-datastream", ip="10.0.0.20", port=9100)

    assert list(service.resources()) == []


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


def test_samba_status_text_reports_smbclient_missing_instead_of_no_shares_found():
    """Verify that Samba.status_text distinguishes a missing smbclient binary from
    a genuinely empty listing, even though both leave shares=[] - conflating them
    used to make a device with SMB actually running masquerade as having none."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = []
    service.smbclient_missing = True

    assert service.status_text == "smbclient not installed"


async def test_samba_fetch_flags_smbclient_missing_without_touching_auth_state(monkeypatch):
    """Verify that Samba.fetch reports smbclient_missing (not auth_required) when
    the smbclient binary itself isn't installed, by forcing HAS_SMBCLIENT False -
    the actual condition on the reporting machine - and checking neither the login
    prompt nor "no shares found" gets shown in its place."""
    monkeypatch.setattr(services, "HAS_SMBCLIENT", False)
    service = Samba(kind="smb", ip="10.0.0.5", port=445, loading=True)

    await service.fetch()

    assert service.loading is False
    assert service.smbclient_missing is True
    assert service.auth_required is False
    assert service.fetch_state == FetchState.LOADED
    assert service.status_text == "smbclient not installed"


@pytest.mark.parametrize("kwargs, expected_state", [
    ({"loading": True}, FetchState.LOADING),
    ({}, FetchState.NOT_FETCHED),
    ({"shares": [SmbShare("Public")]}, FetchState.LOADED),
    ({"auth_required": True}, FetchState.AUTH_REQUIRED),
    # loading wins over every other conflicting state, matching status_text.
    ({"loading": True, "auth_required": True}, FetchState.LOADING),
    # auth_required wins over "shares is None" - a failed fetch also leaves shares
    # as None, so NOT_FETCHED would misreport an auth failure as never attempted.
    ({"shares": None, "auth_required": True}, FetchState.AUTH_REQUIRED),
])
def test_samba_fetch_state_reflects_loading_auth_and_shares(kwargs, expected_state):
    """Verify that Samba.fetch_state derives the right FetchState from its
    loading/auth_required/shares fields, across every state and the two ordering
    cases (loading beats auth_required; auth_required beats "shares is None")."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445, **kwargs)

    assert service.fetch_state == expected_state


@pytest.mark.parametrize("kwargs, expected_fields", [
    ({}, ()),
    ({"shares": [SmbShare("Public")]}, ()),
    ({"auth_required": True}, ("user", "password")),
])
def test_samba_fetch_fields_is_non_empty_only_when_auth_required(kwargs, expected_fields):
    """Verify that Samba.fetch_fields only ever asks for user/password when
    fetch_state is AUTH_REQUIRED, and is empty for every other state."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445, **kwargs)

    assert service.fetch_fields() == expected_fields


async def test_samba_fetch_records_a_successful_anonymous_listing(fake_smbclient):
    """Verify that Samba.fetch stores the shares parsed from a real smbclient-style
    grepable listing and clears auth_required, by configuring the process-boundary
    fixture with a successful output - exercising list_smb_shares's own parsing too."""
    fake_smbclient(stdout="Disk|Public|\nDisk|Media|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445, loading=True)

    await service.fetch()

    assert service.loading is False
    assert service.shares == [SmbShare("Public"), SmbShare("Media")]
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

    assert shares == [SmbShare("Public"), SmbShare("Media")]
    assert printers == [SmbShare("OfficeLaser")]


async def test_samba_fetch_stores_both_shares_and_printers(fake_smbclient):
    """Verify that Samba.fetch stores both lists from a mixed listing, by checking
    both fields land on the service after a fetch that includes a printer share."""
    fake_smbclient(stdout="Disk|Public|\nPrinter|OfficeLaser|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    await service.fetch()

    assert service.shares == [SmbShare("Public")]
    assert service.printers == [SmbShare("OfficeLaser")]


async def test_samba_fetch_records_the_username_behind_a_successful_credentialed_listing(fake_smbclient):
    """Verify that Samba.fetch remembers which username a successful listing was
    made with, so links built from it (see resources()) can carry it through
    instead of prompting the file manager to ask for it again."""
    fake_smbclient(stdout="Disk|Public|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    await service.fetch(user="bob", password="secret")

    assert service.username == "bob"


async def test_samba_fetch_leaves_username_unset_for_an_anonymous_listing(fake_smbclient):
    """Verify that Samba.fetch doesn't record a username for an anonymous fetch, so
    an anonymous listing's links stay plain smb://host/share uris."""
    fake_smbclient(stdout="Disk|Public|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    await service.fetch()

    assert service.username is None


async def test_samba_fetch_clears_a_stale_username_after_a_failed_credentialed_retry(fake_smbclient):
    """Verify that a failed credentialed re-fetch clears any username left over from
    an earlier successful one, so a subsequent stale link isn't built with
    credentials that no longer resolve to a listing."""
    fake_smbclient(stdout="Disk|Public|\n")
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    await service.fetch(user="bob", password="secret")

    fake_smbclient(stdout="", returncode=1)
    await service.fetch(user="bob", password="wrong")

    assert service.username is None


def test_samba_shares_and_printers_coerce_bare_strings_to_smbshare():
    """Verify that assigning shares/printers as bare strings wraps each into an
    SmbShare with an empty comment - so a caller that doesn't care about comments
    (a quick script, a test) can assign plain names without importing SmbShare -
    while an already-typed SmbShare (e.g. one with a real comment) passes through
    unchanged."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    service.shares = ["Public", SmbShare("Media", "already typed")]

    assert service.shares == [SmbShare("Public"), SmbShare("Media", "already typed")]


@pytest.mark.parametrize("kwargs", [
    {},  # NOT_FETCHED
    {"auth_required": True},  # AUTH_REQUIRED - the login prompt itself is built
    # entirely in ui/base.py from fetch_state, not by Samba - see
    # test_ui_base.py's _build_entry tests.
])
def test_samba_resources_yields_nothing_before_a_fetch_has_landed(kwargs):
    """Verify that Samba.resources() yields nothing until shares has actually been
    populated by a successful fetch - covers both NOT_FETCHED and AUTH_REQUIRED,
    which both leave shares as None. Triggering the fetch (NOT_FETCHED) and
    surfacing a login prompt (AUTH_REQUIRED) are both the caller's job now, not
    this method's - see NetworkScanner.ensure_fetched and ui/base.py."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445, **kwargs)

    assert list(service.resources()) == []


def test_samba_resources_yields_both_shares_and_printers_together():
    """Verify that Samba.resources yields both disk shares and printer shares
    together - smb is single-category (see SERVICE_CATEGORIES's comment: both
    share types come from the same fetch and belong in the same File Shares tab,
    rather than splitting printer shares into their own dedicated tab that would be
    a dead label whenever there are none)."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = [SmbShare("Public")]
    service.printers = [SmbShare("OfficeLaser")]

    yielded = list(service.resources())

    assert {r.action.uri for r in yielded} == {"smb://10.0.0.5/Public", "smb://10.0.0.5/OfficeLaser"}
    assert all(isinstance(r.action, LaunchAction) for r in yielded)
    # Not immediate: a share/printer link is only worth showing once its device
    # row is expanded, never in the always-visible Overview row.
    assert all(not r.immediate for r in yielded)


def test_ssh_resources_marks_the_sftp_browser_as_non_immediate():
    """Verify that Ssh.resources marks the terminal launch as immediate (shown in
    the collapsed row's Overview) but the sftp browser as not (only revealed once
    expanded) - the exact distinction Resource.immediate exists to preserve now
    that resources() itself yields everything unconditionally."""
    service = Ssh(kind="ssh", ip="10.0.0.5", port=22)

    yielded = list(service.resources())

    assert [(r.category, r.immediate) for r in yielded] == [
        (ResourceCategory.TERMINAL, True),
        (ResourceCategory.FILE_SHARES, False),
    ]


def test_ssh_enrich_device_stores_the_device_and_still_offers_its_own_alias():
    """Verify that Ssh.enrich_device (which overrides the base Service.enrich_device
    to also remember its owning device - see _host) still offers its own mDNS
    instance name as an alias exactly like the base implementation does, so
    overriding it didn't silently drop that behavior."""
    device = DeviceFactory(ip="10.0.0.5")
    service = Ssh(kind="ssh", ip="10.0.0.5", port=22, discovered_name="werner")

    service.enrich_device(device)

    assert device.names["werner"] == {"ssh"}


def test_ssh_resources_uses_the_devices_known_hosts_name_once_attached():
    """Verify that Ssh.resources builds its sftp browse link from the owning
    Device's ssh_host() (a known_hosts name here) rather than the service's own
    bare ip, once attached via Device.add_service (which calls enrich_device) -
    the same fix as Samba's smb:// links, just for the sftp:// browse action."""
    device = DeviceFactory(ip="10.0.0.5", names={"werner": {"ssh-known-hosts"}})
    device.add_service("ssh", 22)

    sftp = next(r.action for r in device.services["ssh"].resources()
                if r.category == ResourceCategory.FILE_SHARES)

    assert sftp.ip == "werner"


def test_ssh_resources_falls_back_to_ip_when_never_attached_to_a_device():
    """Verify that Ssh.resources still falls back to its own bare ip when built
    directly rather than through Device.add_service - enrich_device never ran, so
    there's no device to ask for a better name."""
    service = Ssh(kind="ssh", ip="10.0.0.5", port=22)

    sftp = next(r.action for r in service.resources() if r.category == ResourceCategory.FILE_SHARES)

    assert sftp.ip == "10.0.0.5"


def test_samba_share_action_builds_an_smb_uri_labeled_with_the_share_name():
    """Verify that Samba._share_action builds an smb:// uri for the given share and
    labels the button with the share's own name, by checking both fields on an
    anonymous (no stored username) service."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    action = service._share_action(SmbShare("Public"))

    assert action.uri == "smb://10.0.0.5/Public"
    assert action.label == "Public"


def test_samba_share_action_url_encodes_a_username_with_special_characters():
    """Verify that a stored username containing a uri-significant character (here,
    '@', as in a UPN-style login) is percent-encoded rather than corrupting the
    uri's own authority/path split."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445, username="bob@example.com")

    action = service._share_action(SmbShare("Public"))

    assert action.uri == "smb://bob%40example.com@10.0.0.5/Public"


def test_samba_printer_action_builds_an_smb_uri_labeled_with_the_printer_name():
    """Verify that Samba._printer_action builds the same smb://-style uri shape as
    _share_action, just for a printer share's name."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445, username="bob")

    action = service._printer_action(SmbShare("OfficeLaser"))

    assert action.uri == "smb://bob@10.0.0.5/OfficeLaser"
    assert action.label == "OfficeLaser"


def test_samba_enrich_device_stores_the_device_and_still_offers_its_own_alias():
    """Verify that Samba.enrich_device (which overrides the base Service.enrich_device
    to also remember its owning device - see _host) still offers its own mDNS
    instance name as an alias exactly like the base implementation does, so
    overriding it didn't silently drop that behavior."""
    device = DeviceFactory(ip="10.0.0.5")
    service = Samba(kind="smb", ip="10.0.0.5", port=445, discovered_name="MyNAS")

    service.enrich_device(device)

    assert device.names["MyNAS"] == {"smb"}


def test_samba_share_action_uses_the_devices_wsd_name_once_attached():
    """Verify that Samba._share_action builds its smb:// uri from the owning
    Device's smb_host() (a wsdd name here) rather than the service's own bare ip,
    once attached via Device.add_service (which calls enrich_device) - the actual
    fix for smb:// links always connecting by ip even when a real name is known."""
    device = DeviceFactory(ip="10.0.0.5", names={"NAS": {"WSD"}})
    device.add_service("smb", 445)
    service = device.services["smb"]

    action = service._share_action(SmbShare("Public"))

    assert action.uri == "smb://NAS/Public"


def test_samba_share_action_falls_back_to_ip_when_never_attached_to_a_device():
    """Verify that Samba._share_action still falls back to its own bare ip when
    built directly rather than through Device.add_service (as every other
    _share_action test here does) - enrich_device never ran, so there's no device to
    ask for a better name."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)

    action = service._share_action(SmbShare("Public"))

    assert action.uri == "smb://10.0.0.5/Public"


def test_samba_resources_carries_the_stored_username_into_both_actions():
    """Verify that Samba.resources passes its own remembered username through to
    both _share_action and _printer_action, by checking each built uri embeds it -
    the actual fix for links otherwise re-prompting for a username already given
    once via the sign-in form."""
    service = Samba(kind="smb", ip="10.0.0.5", port=445)
    service.shares = [SmbShare("Public")]
    service.printers = [SmbShare("OfficeLaser")]
    service.username = "bob"

    yielded = list(service.resources())

    assert {r.action.uri for r in yielded} == {"smb://bob@10.0.0.5/Public", "smb://bob@10.0.0.5/OfficeLaser"}


@pytest.mark.parametrize("kwargs, expected_state", [
    ({"loading": True}, FetchState.LOADING),
    ({}, FetchState.NOT_FETCHED),
    ({"instances": []}, FetchState.LOADED),
    # inaccessible (accessible=False) is still a completed fetch, not an auth
    # prompt - Incus has no interactive retry flow the way Samba does.
    ({"instances": [], "accessible": False}, FetchState.LOADED),
])
def test_incus_fetch_state_reflects_loading_and_instances(kwargs, expected_state):
    """Verify that Incus.fetch_state derives the right FetchState from its
    loading/instances fields, including that an inaccessible-but-fetched server
    is LOADED, not some separate auth-required state."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443, **kwargs)

    assert service.fetch_state == expected_state


def test_incus_resources_always_yields_the_web_admin_link_even_unfetched():
    """Verify that Incus.resources yields a web-admin resource regardless of
    instance-fetch state, by checking a freshly-created service with no fetch yet
    still yields exactly one immediate LaunchAction pointing at the UI root."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)

    yielded = list(service.resources())

    assert len(yielded) == 1
    assert isinstance(yielded[0].action, LaunchAction)
    assert yielded[0].action.uri == "https://10.0.0.5:8443/ui/"
    assert yielded[0].immediate is True


def test_incus_resources_yields_one_console_action_per_instance():
    """Verify that Incus.resources yields the general web-admin link plus a
    console LaunchAction per fetched instance once populated, by setting instances
    directly - the general link supplements per-instance links rather than being
    replaced by them, so there's always something to click even if the instance
    list turns out to be empty."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)
    service.instances = [IncusInstance("web", "Running"), IncusInstance("db", "Stopped")]

    yielded = list(service.resources())

    assert [r.action.label for r in yielded] == ["Incus admin", "web (Running)", "db (Stopped)"]
    # The general link is immediate (visible collapsed too); per-instance
    # consoles are not - they'd be clutter in the compact row.
    assert [r.immediate for r in yielded] == [True, False, False]


def test_incus_console_action_labels_with_name_and_status():
    """Verify that Incus._console_action labels the button with the instance's name
    and status and points at the UI root, by checking a running-instance example."""
    service = Incus(kind="incus", ip="10.0.0.5", port=8443)

    action = service._console_action(IncusInstance("web-vm", "Running"))

    assert action.label == "web-vm (Running)"
    assert action.uri == "https://10.0.0.5:8443/ui/"


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
    assert service.instances == [IncusInstance("web", "Running"), IncusInstance("db", "Stopped")]
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


@pytest.mark.parametrize("kwargs, expected_state", [
    ({"loading": True}, FetchState.LOADING),
    ({}, FetchState.NOT_FETCHED),
    ({"queues": []}, FetchState.LOADED),
    ({"queues": ["Laser1"]}, FetchState.LOADED),
])
def test_cups_fetch_state_reflects_loading_and_queues(kwargs, expected_state):
    """Verify that Cups.fetch_state derives the right FetchState from its
    loading/queues fields, by checking every state including a genuinely empty
    (zero-queue) successful fetch."""
    service = Cups(kind="cups", ip="10.0.0.40", port=631, **kwargs)

    assert service.fetch_state == expected_state


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


def test_cups_resources_targets_the_specific_queue_sub_path():
    """Verify that Cups.resources builds a per-queue LaunchAction pointing at
    /printers/{queue}, alongside the general web-admin link (see Incus's
    equivalent test for why that's not replaced), by checking a service with
    queues already populated."""
    service = Cups(kind="cups", ip="10.0.0.40", port=631)
    service.queues = ["Laser1"]

    yielded = list(service.resources())

    assert len(yielded) == 2
    assert yielded[-1].action.uri == "http://10.0.0.40:631/printers/Laser1"
    # The general link is immediate (visible collapsed too); the per-queue link
    # is not - same reasoning as Incus's per-instance consoles.
    assert [r.immediate for r in yielded] == [True, False]


def test_ipp_resources_prefers_the_advertised_adminurl():
    """Verify that Ipp.resources uses the adminurl txt record verbatim when
    present instead of guessing a port-80 fallback, by checking the built action's
    uri matches the txt record exactly."""
    service = Ipp(kind="ipp", ip="10.0.0.30", port=631,
                  properties={b"adminurl": b"http://10.0.0.30/hp/device/index.html"})

    yielded = list(service.resources())

    assert yielded[0].action.uri == "http://10.0.0.30/hp/device/index.html"


def test_ipp_resources_falls_back_to_port_80_without_an_adminurl():
    """Verify that Ipp.resources falls back to port 80 on the service's own IP
    when no adminurl txt record is present, by checking the built action's uri."""
    service = Ipp(kind="ipp", ip="10.0.0.31", port=631, properties={})

    yielded = list(service.resources())

    assert yielded[0].action.uri == "http://10.0.0.31:80/"


def test_ipp_resources_yields_exactly_one_immediate_resource():
    """Verify that Ipp.resources always yields exactly one, immediate resource -
    ipp has no deeper, per-resource content to reveal once expanded (unlike
    smb/incus/cups), so its Printers tab must keep showing the same resource
    Overview does; a dead, actionless tab would be a regression for a service
    that plainly has one resource available."""
    service = Ipp(kind="ipp", ip="10.0.0.31", port=631, properties={})

    yielded = list(service.resources())

    assert len(yielded) == 1
    assert yielded[0].immediate is True


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
