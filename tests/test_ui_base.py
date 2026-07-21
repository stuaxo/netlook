"""Unit tests for netlook.ui.base - the shared View Model."""
import json

from netlook.core.models import ResourceCategory, make_service
from netlook.core.services import Cups, Incus, Ipp, LpdPrinterService, PdlStreamService, Samba, Ssh
from netlook.ui.base import (
    NAMES_TAB_ID,
    PROPERTIES_TAB_ID,
    LoginPromptView,
    PropertiesTabView,
    PropertyEntry,
    ViewModelState,
    build_device_row_view,
    device_row_view_to_dict,
    properties_section_ids,
    save_devices_to_json,
    submit_login,
)

from doubles import FakeScanner
from factories import DeviceFactory


async def test_overview_excludes_a_permanently_silent_non_expandable_service():
    """Verify that build_device_row_view leaves a silent, non-expandable service
    (pdl-datastream) out of overview entirely - not a placeholder entry - since it
    has nothing to show and isn't expandable into anything either."""
    device = DeviceFactory()
    device.services["pdl-datastream"] = PdlStreamService(kind="pdl-datastream", ip=device.ip, port=9100)

    view = await build_device_row_view(device, scanner=None)

    assert view.overview == []


async def test_overview_includes_a_service_with_an_immediate_action():
    """Verify that build_device_row_view includes a service's immediate action in
    its overview entry, by checking an ssh service (always launchable) yields one
    labeled action and no [View ...] labels."""
    device = DeviceFactory()
    device.services["ssh"] = Ssh(kind="ssh", ip=device.ip, port=22)

    view = await build_device_row_view(device, scanner=None)

    assert len(view.overview) == 1
    entry = view.overview[0]
    assert entry.kind == "ssh"
    assert [a.label for a in entry.actions] == ["Secure Shell (SSH)"]
    assert entry.view_category_labels == []


async def test_overview_gives_a_view_category_button_per_category_for_an_expandable_actionless_service():
    """Verify that an expandable service with no immediate actions (smb, which is
    always empty when collapsed) gets one label per category it belongs to, by
    checking smb's one (File Shares - smb is single-category; both its share types
    render together there, see SERVICE_CATEGORIES's comment). The label is the bare
    category name (matching the tab it opens exactly, e.g. "File Shares" not "View
    File Shares") - a renderer decides how to present it as a button. Multi-category
    membership itself (iterating ResourceCategory in order, filtering to just the
    ones a service belongs to) is exercised with two categories by ssh's tests
    elsewhere, so a single-category case is enough coverage here. expanded defaults
    to False, so category_tabs (and the fetch they'd trigger for smb's
    not-yet-loaded shares) are never built here - overview alone never touches the
    scanner, which is exactly why lazy loading works."""
    device = DeviceFactory()
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445)

    view = await build_device_row_view(device, scanner=None)

    assert len(view.overview) == 1
    entry = view.overview[0]
    assert entry.actions == []
    assert entry.view_category_labels == [(ResourceCategory.FILE_SHARES, "File Shares")]


async def test_category_tabs_are_empty_when_not_expanded():
    """Verify that build_device_row_view builds no category_tabs at all when
    expanded=False (the default) - not just that they'd render nothing - since
    building them is exactly what would call scanner.ensure_fetched and trigger a
    not-yet-fetched service's lazy load. scanner=None proves this: a device with
    an unfetched smb service builds cleanly with no scanner at all."""
    device = DeviceFactory()
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445)

    view = await build_device_row_view(device, scanner=None, expanded=False)

    assert view.category_tabs == []


async def test_category_tabs_only_include_categories_with_a_matching_service():
    """Verify that build_device_row_view only produces a CategoryTabView for
    categories that actually have a matching service on this device, by checking a
    device with only a (single-category) incus service yields exactly the Virtual
    Machines tab."""
    device = DeviceFactory()
    device.services["incus"] = Incus(kind="incus", ip=device.ip, port=8443, instances=[])

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    assert [tab.category for tab in view.category_tabs] == [ResourceCategory.VIRTUAL_MACHINES]


async def test_category_tabs_include_both_categories_for_a_multi_category_service():
    """Verify that a service spanning two categories (ssh: a terminal launch under
    TERMINAL, an sftp browser under FILE_SHARES - one service, two distinct
    resources) gets a tab for each, by checking a device with only ssh yields both."""
    device = DeviceFactory()
    device.services["ssh"] = Ssh(kind="ssh", ip=device.ip, port=22)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    assert {tab.category for tab in view.category_tabs} == {
        ResourceCategory.TERMINAL, ResourceCategory.FILE_SHARES,
    }
    terminal_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.TERMINAL)
    file_shares_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.FILE_SHARES)
    assert [a.label for a in terminal_tab.entries[0].actions] == ["Secure Shell (SSH)"]
    assert [a.label for a in file_shares_tab.entries[0].actions] == ["browse"]


async def test_category_tab_entry_shows_a_fallback_label_for_a_silent_service():
    """Verify that a category tab's entry for a service with no actions and no
    status_text gets a fallback_label (so the tab isn't blank), by checking
    pdl-datastream's entry in the Printers tab."""
    device = DeviceFactory()
    device.services["pdl-datastream"] = PdlStreamService(kind="pdl-datastream", ip=device.ip, port=9100)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    printers_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.PRINTERS)
    assert len(printers_tab.entries) == 1
    entry = printers_tab.entries[0]
    assert entry.actions == []
    assert entry.fallback_label == "Raw Printing (JetDirect)"


async def test_printers_tab_combines_multiple_services_into_one_grouped_entry():
    """Verify that Printers (a GROUPED_CATEGORIES category) combines every
    matching service's actions into a single entry under one shared header,
    rather than one entry per service - a physical printer that advertises via
    ipp, cups, and pdl-datastream at once is one printer, not three separate
    things to look at. ipp and cups's general links both say "Printer admin"
    (rather than naming their own protocol) since, from this printer's grouped
    perspective, they're just two ways to reach the same conceptual admin page -
    showing the same wording twice here is intentional, not a duplication bug:
    the underlying URIs still differ (ipp's own admin url vs cups's web root)."""
    device = DeviceFactory()
    device.services["ipp"] = Ipp(kind="ipp", ip=device.ip, port=631, properties={})
    device.services["cups"] = Cups(kind="cups", ip=device.ip, port=631, queues=["Laser1"])
    device.services["pdl-datastream"] = PdlStreamService(kind="pdl-datastream", ip=device.ip, port=9100)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    printers_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.PRINTERS)
    assert len(printers_tab.entries) == 1
    entry = printers_tab.entries[0]
    assert entry.kind == "printer-group"
    assert [a.label for a in entry.actions] == ["Printer admin", "Printer admin", "Laser1"]
    assert entry.actions[0].action.uri != entry.actions[1].action.uri
    assert entry.fallback_label is None


async def test_printers_tab_grouped_fallback_combines_every_silent_services_label():
    """Verify that a grouped entry's fallback_label lists every silent service's
    display name when the whole group has nothing clickable, not just the first
    one - the single-service fallback rule (see test above it) generalized across
    a group."""
    device = DeviceFactory()
    device.services["pdl-datastream"] = PdlStreamService(kind="pdl-datastream", ip=device.ip, port=9100)
    device.services["printer"] = LpdPrinterService(kind="printer", ip=device.ip, port=515)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    printers_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.PRINTERS)
    assert len(printers_tab.entries) == 1
    entry = printers_tab.entries[0]
    assert entry.actions == []
    assert entry.fallback_label == "Raw Printing (JetDirect), Print queue (LPD)"


async def test_non_grouped_categories_keep_one_entry_per_service():
    """Verify that a category not listed in GROUPED_CATEGORIES (Screen Share) still
    gets one CategoryEntry per matching service, unaffected by the
    Printers-specific grouping - regression check that grouping is opt-in per
    category, not global. Uses rdp+vnc (both always have a real action) rather
    than device-info+home-assistant, since device-info's entry would now be
    correctly omitted as purely informational - see the dedicated test for that."""
    device = DeviceFactory()
    device.services["rdp"] = make_service("rdp", device.ip, 3389)
    device.services["vnc"] = make_service("vnc", device.ip, 5900)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    screen_share_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.SCREEN_SHARE)
    assert {entry.kind for entry in screen_share_tab.entries} == {"rdp", "vnc"}


async def test_purely_informational_service_gets_no_category_tab_entry():
    """Verify that a service with nothing to show in any state (device-info: no
    launch scheme, no web admin page, never sets loading) gets no CategoryEntry at
    all - not a fallback-label placeholder - since its own header would just
    repeat the exact text a fallback label would show (e.g. "Device Info" over
    "Device Info"). Its info is already reflected in this device's own promoted
    name and in the Properties tab, so nothing is lost by omitting it here."""
    device = DeviceFactory()
    device.services["device-info"] = make_service("device-info", device.ip, 0)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    assert view.category_tabs == []


async def test_category_tab_omits_a_purely_informational_entry_but_keeps_the_rest():
    """Verify that a category with a mix of a purely-informational service
    (device-info) and a real one (home-assistant) only builds a tab entry for the
    real one - the informational service is dropped silently, not replaced with a
    placeholder, while its sibling's real content still renders normally."""
    device = DeviceFactory()
    device.services["device-info"] = make_service("device-info", device.ip, 0)
    device.services["home-assistant"] = make_service("home-assistant", device.ip, 8123)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    system_tab = next(tab for tab in view.category_tabs if tab.category == ResourceCategory.SYSTEM)
    assert {entry.kind for entry in system_tab.entries} == {"home-assistant"}


async def test_category_tab_triggers_a_fetch_via_scanner_when_data_not_yet_loaded():
    """Verify that building the view for a category tab whose service hasn't fetched
    yet (smb with shares=None) requests items via the scanner, by checking a
    FakeScanner recorded the call. Only happens when expanded=True - this is the
    counterpart to test_category_tabs_are_empty_when_not_expanded."""
    device = DeviceFactory()
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445)
    scanner = FakeScanner()

    await build_device_row_view(device, scanner=scanner, expanded=True)

    assert len(scanner.requested) >= 1
    assert scanner.requested[0][0] is device.services["smb"]


async def test_category_tab_triggers_a_fetch_via_scanner_when_incus_instances_not_yet_loaded():
    """Verify that building the view for a category tab whose Incus service hasn't
    fetched yet (instances=None) requests items via the scanner too - the Incus
    analog of the smb test above, confirming ensure_fetched's gating isn't
    Samba-specific."""
    device = DeviceFactory()
    device.services["incus"] = Incus(kind="incus", ip=device.ip, port=8443)
    scanner = FakeScanner()

    await build_device_row_view(device, scanner=scanner, expanded=True)

    assert len(scanner.requested) >= 1
    assert scanner.requested[0][0] is device.services["incus"]


async def test_category_tab_does_not_re_trigger_a_fetch_when_auth_required():
    """Verify that build_device_row_view does NOT call scanner.request_items for a
    Samba service that's already AUTH_REQUIRED - regression guard for the same bug
    a prior version of Samba.get_resources had to check auth_required before
    "shares is None" to avoid: ensure_fetched only acts on NOT_FETCHED, so an
    auth-required service correctly gets a login prompt instead of looping another
    anonymous fetch."""
    device = DeviceFactory()
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445, auth_required=True)
    scanner = FakeScanner()

    await build_device_row_view(device, scanner=scanner, expanded=True)

    assert scanner.requested == []


async def test_build_entry_surfaces_a_login_prompt_for_an_auth_required_service():
    """Verify that an AUTH_REQUIRED service's category tab entry carries a
    LoginPromptView (fields from fetch_fields, failed from tried_auth, and the
    live service reference) instead of actions/status_text/fallback_label."""
    device = DeviceFactory()
    smb = Samba(kind="smb", ip=device.ip, port=445, auth_required=True, tried_auth=True)
    device.services["smb"] = smb

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)

    file_shares_tab = next(t for t in view.category_tabs if t.category == ResourceCategory.FILE_SHARES)
    entry = file_shares_tab.entries[0]
    assert entry.actions == []
    assert entry.status_text is None
    assert entry.fallback_label is None
    assert entry.login.fields == ("user", "password")
    assert entry.login.failed is True
    assert entry.login.service is smb


async def test_submit_login_re_queries_the_owning_service_via_scanner():
    """Verify that submit_login calls scanner.request_items with the trimmed
    username and the login prompt's owning service, by capturing the call on a
    fake scanner - the login-prompt equivalent of what CredentialAction.run used
    to do, now that a login prompt isn't an Action at all."""
    device = DeviceFactory()
    smb = Samba(kind="smb", ip=device.ip, port=445, auth_required=True)
    login = LoginPromptView(fields=("user", "password"), service=smb, failed=False)
    scanner = FakeScanner()

    await submit_login(scanner, login, user="  bob  ", password="secret")

    assert scanner.requested == [(smb, {"user": "bob", "password": "secret"})]


async def test_properties_decodes_raw_txt_records_and_sorts_by_kind():
    """Verify that the Properties view decodes raw bytes TXT records into plain
    strings and orders services alphabetically by kind, by checking a service with
    properties against one with none. properties is always built regardless of
    expanded, unlike category_tabs - it only reads already-discovered
    service.properties, never triggering a fetch - so scanner=None is fine here."""
    device = DeviceFactory()
    device.services["ssh"] = Ssh(kind="ssh", ip=device.ip, port=22)
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445, properties={b"vers": b"3.0"})

    view = await build_device_row_view(device, scanner=None)

    assert [p.kind for p in view.properties.services] == ["smb", "ssh"]
    smb_props, ssh_props = view.properties.services
    assert smb_props.properties == [("vers", "3.0")]
    assert ssh_props.properties == []


async def test_properties_leads_with_a_services_extra_properties_before_its_txt_records():
    """Verify that a service's extra_properties (runtime diagnostic detail with no
    mDNS TXT record of its own - see Incus.error) appear first in its Properties
    entry, ahead of its raw advertised TXT records - it's what a user investigating
    a problem is most likely looking for."""
    device = DeviceFactory()
    device.services["incus"] = Incus(
        kind="incus", ip=device.ip, port=8443, properties={b"foo": b"bar"},
        accessible=False, error="not authorized",
    )

    view = await build_device_row_view(device, scanner=None)

    incus_props = next(p for p in view.properties.services if p.kind == "incus")
    assert incus_props.properties == [("error", "not authorized"), ("foo", "bar")]


async def test_properties_carries_physical_interfaces_through_from_the_device():
    """Verify that the Properties view's physical_devices reflects
    Device.physical_interfaces directly, by checking a device with one set."""
    device = DeviceFactory()
    device.physical_interfaces = [("wlan0", "aa:bb:cc:dd:ee:ff")]

    view = await build_device_row_view(device, scanner=None)

    assert view.properties.physical_devices == [("wlan0", "aa:bb:cc:dd:ee:ff")]


async def test_properties_physical_devices_is_empty_without_any():
    """Verify that the Properties view's physical_devices is empty for an ordinary
    device (Device.physical_interfaces defaults to []) - the case for every device
    except this machine's own, which is what a renderer uses to decide whether to
    show the Physical Devices section at all."""
    device = DeviceFactory()

    view = await build_device_row_view(device, scanner=None)

    assert view.properties.physical_devices == []


def test_view_model_state_toggle_expanded_flips_membership():
    """Verify that ViewModelState.toggle_expanded adds an ip the first time and
    removes it the second, by calling it twice and checking is_expanded after each."""
    state = ViewModelState()

    state.toggle_expanded("10.0.0.5")
    assert state.is_expanded("10.0.0.5") is True

    state.toggle_expanded("10.0.0.5")
    assert state.is_expanded("10.0.0.5") is False


def test_view_model_state_expand_never_collapses_an_already_open_row():
    """Verify that ViewModelState.expand only ever adds, unlike toggle_expanded, by
    calling it twice on the same ip and checking it stays expanded."""
    state = ViewModelState()

    state.expand("10.0.0.5")
    state.expand("10.0.0.5")

    assert state.is_expanded("10.0.0.5") is True


def test_get_active_tab_defaults_to_names_without_a_request():
    """Verify that get_active_tab falls back to NAMES_TAB_ID for an ip with no
    recorded request, so a device expanded via the plain disclosure arrow (not a
    [View <Category>] button) still lands somewhere sensible."""
    state = ViewModelState()

    assert state.get_active_tab("10.0.0.5") == NAMES_TAB_ID


def test_expand_with_a_category_also_records_it_as_the_active_tab():
    """Verify that expand(ip, category=...) - what a [View <Category>] button's
    handler calls - both opens the row and records that category as the tab to land
    on, by checking get_active_tab reflects it afterward."""
    state = ViewModelState()

    state.expand("10.0.0.5", category=ResourceCategory.FILE_SHARES)

    assert state.is_expanded("10.0.0.5") is True
    assert state.get_active_tab("10.0.0.5") == ResourceCategory.FILE_SHARES.name


def test_set_active_tab_overrides_a_previously_requested_tab():
    """Verify that set_active_tab - what a renderer calls when the user manually
    switches tabs - overrides whatever was requested via expand(category=...), so a
    manual switch always wins over the original [View <Category>] request."""
    state = ViewModelState()
    state.expand("10.0.0.5", category=ResourceCategory.FILE_SHARES)

    state.set_active_tab("10.0.0.5", PROPERTIES_TAB_ID)

    assert state.get_active_tab("10.0.0.5") == PROPERTIES_TAB_ID


async def test_device_row_view_to_dict_includes_names_and_properties():
    """Verify that device_row_view_to_dict produces the expected top-level shape,
    by checking a device with a hostname, an alias, and a property lands in the
    right places."""
    device = DeviceFactory(hostname="MyNAS", names={"MyNAS": {"smb"}, "nas.lan": {"etc-hosts"}})
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445, properties={b"vers": b"3.0"})

    view = await build_device_row_view(device, scanner=None)
    result = device_row_view_to_dict(view)

    assert result["ip"] == device.ip
    assert result["hostname"] == "MyNAS"
    assert result["names"]["aliases"] == {"nas.lan": ["etc-hosts"]}
    assert result["properties"]["services"] == [{"kind": "smb", "port": 445, "properties": [["vers", "3.0"]]}]


async def test_device_row_view_to_dict_extracts_only_label_fields_uri_from_actions():
    """Verify that an action serializes to just {label, fields, uri} - not a blind
    dump of the underlying Action object - by checking Ssh's form-backed sftp
    browse action (which genuinely has fields)."""
    device = DeviceFactory()
    device.services["ssh"] = Ssh(kind="ssh", ip=device.ip, port=22)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)
    result = device_row_view_to_dict(view)

    file_shares_tab = next(t for t in result["category_tabs"] if t["category"] == "File Shares")
    action = file_shares_tab["entries"][0]["actions"][0]
    assert set(action.keys()) == {"label", "fields", "uri"}
    assert action["fields"] == ["user", "path"]


async def test_device_row_view_to_dict_carries_login_fields_when_auth_required():
    """Verify that an AUTH_REQUIRED service's category-tab entry serializes its
    login_fields rather than a fake action - the regression this dump shape
    exists to represent correctly, since a login prompt isn't an Action at all
    and its live service reference (LoginPromptView.service) must never leak into
    the JSON output the way CredentialAction.service risked doing before it."""
    device = DeviceFactory()
    device.services["smb"] = Samba(kind="smb", ip=device.ip, port=445, auth_required=True)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)
    result = device_row_view_to_dict(view)

    file_shares_tab = next(t for t in result["category_tabs"] if t["category"] == "File Shares")
    entry = file_shares_tab["entries"][0]
    assert entry["actions"] == []
    assert entry["login_fields"] == ["user", "password"]


async def test_device_row_view_to_dict_login_fields_is_null_when_not_auth_required():
    """Verify that login_fields is present but null for a normal (non-auth-gated)
    category-tab entry, matching status_text/fallback_label's own nullable
    convention."""
    device = DeviceFactory()
    device.services["ssh"] = Ssh(kind="ssh", ip=device.ip, port=22)

    view = await build_device_row_view(device, scanner=FakeScanner(), expanded=True)
    result = device_row_view_to_dict(view)

    terminal_tab = next(t for t in result["category_tabs"] if t["category"] == "Terminal")
    assert terminal_tab["entries"][0]["login_fields"] is None


async def test_save_devices_to_json_writes_saved_at_and_one_entry_per_view(tmp_path):
    """Verify that save_devices_to_json writes a real file containing a saved_at
    timestamp and one entry per given view, by round-tripping two built views
    through a real file write/read - the file system is the true external edge
    here, not something to mock."""
    path = tmp_path / "devices.json"
    nas = DeviceFactory(hostname="MyNAS")
    printer = DeviceFactory(hostname="Printer")
    views = [await build_device_row_view(dev, scanner=None) for dev in (nas, printer)]

    save_devices_to_json(views, path=str(path))

    data = json.loads(path.read_text())
    assert "saved_at" in data
    assert [d["hostname"] for d in data["devices"]] == ["MyNAS", "Printer"]


def test_properties_section_ids_matches_what_a_renderer_would_actually_show():
    """Verify that properties_section_ids includes "physical_devices" (only when
    non-empty) then each service with at least one non-blank-keyed property, in
    order - skipping a service whose only properties are blank-keyed (matching a
    renderer's own skip condition exactly), so Expand All/Collapse All never
    targets a section that was never drawn."""
    properties = PropertiesTabView(
        ip="10.0.0.5", ipv6=None,
        services=[
            PropertyEntry(kind="smb", port=445, properties=[("vers", "3.0")]),
            PropertyEntry(kind="blank-only", port=1, properties=[("", "(present, no value)")]),
            PropertyEntry(kind="empty", port=2, properties=[]),
        ],
        physical_devices=[("wlan0", "aa:bb:cc:dd:ee:ff")],
    )

    assert properties_section_ids(properties) == ["physical_devices", "smb"]


def test_properties_section_ids_omits_physical_devices_when_empty():
    """Verify that properties_section_ids leaves out "physical_devices" entirely
    when there are none, matching a renderer never drawing that section either."""
    properties = PropertiesTabView(
        ip="10.0.0.5", ipv6=None,
        services=[PropertyEntry(kind="smb", port=445, properties=[("vers", "3.0")])],
        physical_devices=[],
    )

    assert properties_section_ids(properties) == ["smb"]


def test_view_model_state_properties_section_expansion_defaults_to_collapsed():
    """Verify that is_properties_section_expanded defaults to False for a section
    that's never been recorded - a newly-seen device's Properties sections start
    closed, per the default this feature was built for."""
    state = ViewModelState()

    assert state.is_properties_section_expanded("10.0.0.5", "smb") is False


def test_view_model_state_set_properties_section_expanded_round_trips():
    """Verify that set_properties_section_expanded records exactly the value given,
    read back via is_properties_section_expanded, and that it's scoped per (ip,
    section_id) - the same section_id on a different ip isn't affected."""
    state = ViewModelState()

    state.set_properties_section_expanded("10.0.0.5", "smb", True)

    assert state.is_properties_section_expanded("10.0.0.5", "smb") is True
    assert state.is_properties_section_expanded("10.0.0.6", "smb") is False


def test_view_model_state_all_properties_expanded_requires_every_section():
    """Verify that all_properties_expanded is True only once every given section_id
    is individually expanded - partially expanded, or none at all, isn't enough -
    and False for a device with no sections at all, since there's nothing to call
    "all expanded"."""
    state = ViewModelState()
    state.set_properties_section_expanded("10.0.0.5", "smb", True)

    assert state.all_properties_expanded("10.0.0.5", ["smb", "ssh"]) is False

    state.set_properties_section_expanded("10.0.0.5", "ssh", True)

    assert state.all_properties_expanded("10.0.0.5", ["smb", "ssh"]) is True
    assert state.all_properties_expanded("10.0.0.5", []) is False
