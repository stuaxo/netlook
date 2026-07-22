"""Interaction tests for netlook.ui.textual, using Textual's own Pilot test
harness - app.run_test() drives real widget composition/layout/click dispatch, the
same "test real behavior, mock only at true external edges" philosophy as the rest
of this suite (popen_calls is the one genuine external edge Action.run() touches)."""
import json

import pytest
from textual.widgets import Button, Collapsible, TabbedContent, TabPane

from netlook.core.models import Device
from netlook.core.scanner import NetworkScanner
from netlook.core.services import PdlStreamService, SmbShare
from netlook.ui.base import DEFAULT_SAVE_PATH
from netlook.ui.textual import NetworkBrowserApp

# Wide enough that a row's inline content (arrow + hostname + ip + several buttons)
# never overflows off-screen, which would make Pilot.click raise OutOfBounds.
PILOT_SIZE = (160, 50)


@pytest.fixture
def app_with_device():
    """A NetworkBrowserApp wired to a NetworkScanner with no discovery engines (never
    touches the real network) and one pre-populated device: smb (already fetched,
    one share, no printers - so it's expandable but has no immediate action) and ssh
    (always has an immediate launch action)."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5", names={"MyNAS": {"device-info"}})
    dev.add_service("_smb._tcp.local.", 445, {}, "MyNAS")
    smb = dev.services["smb"]
    smb.shares = [SmbShare("Public")]
    smb.printers = []
    dev.add_service("_ssh._tcp.local.", 22, {}, None)
    scanner.devices["10.0.0.5"] = dev
    return NetworkBrowserApp(scanner=scanner)


async def test_collapsed_row_shows_immediate_actions_and_view_category_buttons(app_with_device):
    """Verify the collapsed row shows ssh's immediate action button plus smb's File
    Shares category button (smb has no immediate actions, only a category), by
    checking the full set of button labels rendered. The category button's label is
    the bare category name, matching the tab it opens exactly."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()

        labels = {str(b.label) for b in app_with_device.query(Button)}

        assert "Secure Shell (SSH)" in labels
        assert "File Shares" in labels


async def test_clicking_the_toggle_arrow_expands_the_row(app_with_device):
    """Verify that clicking the disclosure arrow expands the device row, by checking
    view_state after the click."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        toggle = next(b for b in app_with_device.query(Button) if getattr(b, "is_toggle", False))

        await pilot.click(toggle)
        await pilot.pause()

        assert app_with_device.view_state.is_expanded("10.0.0.5") is True


async def test_view_category_button_expands_the_row(app_with_device):
    """Verify that clicking smb's File Shares category button expands the row. The
    button only ever renders in the collapsed row now (not duplicated into the
    already-open Overview tab), so unlike before, it can't literally be clicked a
    second time through the same still-mounted widget once expanded; the underlying
    expand-not-toggle semantics (ViewModelState.expand never collapses) are covered
    directly in test_ui_base.py, since that's what the button's handler calls."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        view_button = next(b for b in app_with_device.query(Button) if str(b.label) == "File Shares")

        await pilot.click(view_button)
        await pilot.pause()

        assert app_with_device.view_state.is_expanded("10.0.0.5") is True


async def test_view_category_button_opens_directly_to_that_tab(app_with_device):
    """Verify that clicking smb's File Shares category button doesn't just expand
    the row, it lands the TabbedContent on File Shares specifically, rather than
    always defaulting to the first (Names) tab - the whole point of the button
    being labeled by category in the first place."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        view_button = next(b for b in app_with_device.query(Button) if str(b.label) == "File Shares")

        await pilot.click(view_button)
        await pilot.pause()

        tabbed = app_with_device.query_one(TabbedContent)
        assert tabbed.active == "tab-FILE_SHARES"


async def test_manually_switching_tabs_survives_an_unrelated_refresh(app_with_device):
    """Verify that manually switching to a different tab sticks across a later
    unrelated refresh_now() call - which fully rebuilds every DeviceRow from
    scratch (there's no widget to just leave alone) - rather than silently
    resetting back to Names, since nothing about an unrelated scanner change
    should yank the user away from what they're looking at."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app_with_device.view_state.expand("10.0.0.5")
        await app_with_device.refresh_now()
        await pilot.pause()

        tabbed = app_with_device.query_one(TabbedContent)
        tabbed.active = "tab-FILE_SHARES"
        await pilot.pause()

        await app_with_device.refresh_now()
        await pilot.pause()

        tabbed = app_with_device.query_one(TabbedContent)
        assert tabbed.active == "tab-FILE_SHARES"


async def test_clicking_an_action_button_runs_its_action(app_with_device, popen_calls, monkeypatch):
    """Verify that clicking a plain action button (ssh's launch action) invokes
    Action.run, by checking the resulting Popen command. Forces HAS_REMMINA False so
    the expected command is deterministic regardless of whether remmina happens to
    be installed on the machine running the tests."""
    from netlook.core import actions as actions_module

    monkeypatch.setattr(actions_module, "HAS_REMMINA", False)

    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        ssh_button = next(b for b in app_with_device.query(Button) if str(b.label) == "Secure Shell (SSH)")

        await pilot.click(ssh_button)
        await pilot.pause()

        assert popen_calls == [["xdg-open", "ssh://10.0.0.5:22"]]


async def test_names_tab_is_labeled_with_the_hostname_and_shows_identity(app_with_device):
    """Verify that the first tab (Names, replacing the old Overview) is labeled with
    the device's own current hostname and shows its identity - not action buttons,
    which live only in the collapsed row and the real category tabs now."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        toggle = next(b for b in app_with_device.query(Button) if getattr(b, "is_toggle", False))
        await pilot.click(toggle)
        await pilot.pause()

        names_pane = app_with_device.query_one(TabbedContent).get_pane("tab-names")

        assert len(names_pane.query(Button)) == 0
        rendered = "\n".join(str(s.content) for s in names_pane.query("Static"))
        assert "MyNAS" in rendered


async def test_category_tabs_are_only_created_for_categories_with_a_matching_service(app_with_device):
    """Verify that expanding the row creates a tab per matching category - File
    Shares (smb's only category now - its printer shares, if any, render inside
    File Shares too rather than a dedicated Printers tab) and Terminal (ssh, which
    also contributes to File Shares via its sftp resource, so it doesn't add any
    category beyond what smb already covers here) - plus Names and Properties, and
    no others (no Printers, Screen Share, Virtual Machines, System, or Other -
    nothing on this device belongs to them)."""
    async with app_with_device.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        toggle = next(b for b in app_with_device.query(Button) if getattr(b, "is_toggle", False))

        await pilot.click(toggle)
        await pilot.pause()

        tab_ids = {pane.id for pane in app_with_device.query(TabPane)}

        assert tab_ids == {"tab-names", "tab-FILE_SHARES", "tab-TERMINAL", "tab-properties"}


async def test_category_tab_shows_a_fallback_label_for_a_silent_service():
    """Verify that a category tab shows a fallback label for a service with no
    actions (pdl-datastream in the Printers tab), so the tab isn't blank, by
    expanding the row and reading that tab's rendered text."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("Printer", "10.0.0.40")
    dev.services["pdl-datastream"] = PdlStreamService(kind="pdl-datastream", ip="10.0.0.40", port=9100)
    scanner.devices["10.0.0.40"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.40")
        await app.refresh_now()
        await pilot.pause()

        printers_pane = app.query_one(TabbedContent).get_pane("tab-PRINTERS")
        rendered = "\n".join(str(s.content) for s in printers_pane.query("Static"))

        assert "Raw Printing (JetDirect)" in rendered


async def test_form_submission_runs_the_action_with_typed_values(monkeypatch, popen_calls):
    """Verify that filling in and submitting a form action (ssh's sftp browse form)
    runs the action with the typed field values, by checking the resulting Popen
    command includes the typed username. The sftp resource lives under File Shares
    now (ssh spans Terminal + File Shares - see Ssh.resources), not Terminal.
    Pinned to the plain-xdg-open path (see test_actions.py for the gio-open/
    gtk-launch branch) so this test's own assertion is only about the UI wiring."""
    from textual.widgets import Input

    from netlook.core import actions as actions_module

    monkeypatch.setattr(actions_module, "_uses_gio_open", lambda: False)

    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_ssh._tcp.local.", 22, {}, None)
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()

        # the sftp form lives in the File Shares tab, which isn't active by default -
        # switch to it first, same as a real user clicking the tab
        tabbed = app.query_one(TabbedContent)
        tabbed.active = "tab-FILE_SHARES"
        await pilot.pause()

        user_input = next(inp for inp in app.query(Input) if inp.placeholder == "user")
        user_input.value = "bob"
        browse_button = next(b for b in app.query(Button) if str(b.label) == "browse")

        await pilot.click(browse_button)
        await pilot.pause()

        assert popen_calls == [["xdg-open", "sftp://bob@10.0.0.5"]]


async def test_login_form_submission_calls_request_items_with_typed_credentials():
    """Verify that filling in and submitting the login form (smb's sign-in prompt,
    shown once auth_required) calls scanner.request_items with the typed
    credentials, by monkeypatching request_items to capture the call - the
    login-prompt equivalent of test_form_submission_runs_the_action_with_typed_values
    above (which exercises a real Action.run()); this exercises submit_login's
    scanner.request_items hand-off instead, since a login prompt isn't an Action
    at all. No prior coverage existed for this path - filling a real gap, not
    updating an existing test."""
    from textual.widgets import Input

    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_smb._tcp.local.", 445, {}, "MyNAS")
    dev.services["smb"].auth_required = True
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    calls = []

    async def fake_request_items(service, **kwargs):
        calls.append((service, kwargs))

    scanner.request_items = fake_request_items

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()

        tabbed = app.query_one(TabbedContent)
        tabbed.active = "tab-FILE_SHARES"
        await pilot.pause()

        user_input = next(inp for inp in app.query(Input) if inp.placeholder == "user")
        user_input.value = "bob"
        password_input = next(inp for inp in app.query(Input) if inp.placeholder == "password")
        password_input.value = "secret"
        submit_button = next(b for b in app.query(Button) if str(b.label) == "sign in")

        await pilot.click(submit_button)
        await pilot.pause()

        assert calls == [(dev.services["smb"], {"user": "bob", "password": "secret"})]


async def test_properties_tab_shows_decoded_txt_records():
    """Verify that the Properties tab renders a service's decoded TXT records as
    plain text, by checking the rendered Static content includes the key/value."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_smb._tcp.local.", 445, {b"vers": b"3.0"}, "MyNAS")
    dev.services["smb"].shares = []
    dev.services["smb"].printers = []
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()

        properties_pane = app.query_one(TabbedContent).get_pane("tab-properties")
        rendered = "\n".join(str(s.content) for s in properties_pane.query("Static"))

        assert "vers = 3.0" in rendered


async def test_properties_sections_default_to_collapsed():
    """Verify that a Properties tab's sections start collapsed - this tab gets
    long, so nothing should be expanded until the user asks for it."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_smb._tcp.local.", 445, {b"vers": b"3.0"}, "MyNAS")
    dev.services["smb"].shares = []
    dev.services["smb"].printers = []
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()

        properties_pane = app.query_one(TabbedContent).get_pane("tab-properties")
        # "Finders" (always shown) + "smb" - both start collapsed.
        assert [c.collapsed for c in properties_pane.query(Collapsible)] == [True, True]


async def test_expand_all_button_expands_every_section_and_flips_its_own_label():
    """Verify that clicking the Expand All button immediately expands every
    Properties section on that device and relabels itself to Collapse All -
    without waiting for a refresh, since nothing about which resources exist
    changed."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_smb._tcp.local.", 445, {b"vers": b"3.0"}, "MyNAS")
    dev.services["smb"].shares = []
    dev.services["smb"].printers = []
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()
        # the button needs a real on-screen position to be clickable, which a
        # widget in a non-active tab pane never gets
        tabbed = app.query_one(TabbedContent)
        tabbed.active = "tab-properties"
        await pilot.pause()

        toggle_button = next(b for b in app.query(Button) if getattr(b, "is_toggle_all_properties", False))
        assert str(toggle_button.label) == "Expand All"

        await pilot.click(toggle_button)
        await pilot.pause()

        assert str(toggle_button.label) == "Collapse All"
        properties_pane = app.query_one(TabbedContent).get_pane("tab-properties")
        # "Finders" (always shown) + "smb" - both now expanded.
        assert [c.collapsed for c in properties_pane.query(Collapsible)] == [False, False]


async def test_manually_toggling_a_properties_section_survives_an_unrelated_refresh():
    """Verify that manually expanding one Properties section sticks across a later
    unrelated refresh_now() call - which fully rebuilds every DeviceRow from
    scratch - rather than silently resetting back to collapsed."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_smb._tcp.local.", 445, {b"vers": b"3.0"}, "MyNAS")
    dev.services["smb"].shares = []
    dev.services["smb"].printers = []
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()
        tabbed = app.query_one(TabbedContent)
        tabbed.active = "tab-properties"
        await pilot.pause()

        title = app.query_one("CollapsibleTitle")
        await pilot.click(title)
        await pilot.pause()
        assert app.query_one(Collapsible).collapsed is False

        await app.refresh_now()
        await pilot.pause()

        assert app.query_one(Collapsible).collapsed is False


async def test_properties_tab_shows_physical_devices_when_present():
    """Verify that the Properties tab renders a Physical Devices section (this
    machine's own network interfaces, name + MAC) when the device has any, by
    setting Device.physical_interfaces directly on a manually-built device."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("localhost", "192.168.1.5")
    dev.physical_interfaces = [("wlan0", "aa:bb:cc:dd:ee:ff")]
    scanner.devices["192.168.1.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("192.168.1.5")
        await app.refresh_now()
        await pilot.pause()

        properties_pane = app.query_one(TabbedContent).get_pane("tab-properties")
        rendered = "\n".join(str(s.content) for s in properties_pane.query("Static"))

        assert "Physical Devices" in rendered
        assert "wlan0 = aa:bb:cc:dd:ee:ff" in rendered


async def test_properties_tab_omits_physical_devices_section_without_any():
    """Verify that the Properties tab has no Physical Devices section at all for an
    ordinary device (Device.physical_interfaces defaults to []) - not an empty
    section, nothing."""
    scanner = NetworkScanner(discovery_engines=[])
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_smb._tcp.local.", 445, {b"vers": b"3.0"}, "MyNAS")
    dev.services["smb"].shares = []
    dev.services["smb"].printers = []
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        app.view_state.expand("10.0.0.5")
        await app.refresh_now()
        await pilot.pause()

        properties_pane = app.query_one(TabbedContent).get_pane("tab-properties")
        rendered = "\n".join(str(s.content) for s in properties_pane.query("Static"))

        assert "Physical Devices" not in rendered


async def test_save_button_writes_a_json_file_with_all_devices(monkeypatch, tmp_path):
    """Verify that clicking the Save button writes a JSON file containing every
    currently-known device, by chdir'ing into a temp directory (DEFAULT_SAVE_PATH
    is a relative filename) and checking the file exists and is well-formed after
    the click. local_network is a fixed fake value (see conftest.net_scanner) so
    the file's device list is exactly this test's device plus the local-machine
    entry start() always pre-seeds - not whatever the real host's own network
    happens to look like."""
    monkeypatch.chdir(tmp_path)
    scanner = NetworkScanner(discovery_engines=[], local_network=({"127.0.0.1", "192.168.99.1"}, "192.168.99.1"))
    dev = Device("MyNAS", "10.0.0.5")
    dev.add_service("_ssh._tcp.local.", 22, {}, None)
    scanner.devices["10.0.0.5"] = dev
    app = NetworkBrowserApp(scanner=scanner)

    async with app.run_test(size=PILOT_SIZE) as pilot:
        await pilot.pause()
        save_button = next(b for b in app.query(Button) if getattr(b, "is_save", False))

        await pilot.click(save_button)
        await pilot.pause()

        saved_path = tmp_path / DEFAULT_SAVE_PATH
        assert saved_path.exists()
        data = json.loads(saved_path.read_text())
        assert sorted(d["hostname"] for d in data["devices"]) == ["MyNAS", "localhost"]
