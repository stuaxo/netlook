"""Textual TUI frontend. Runs on the same asyncio event loop as the async core (no
threading bridge needed here, unlike ui/dpg.py) - this module can just `await`
scanner/action/get_resources calls directly.

Layout mirrors ui/dpg.py exactly, both reading from the same ui/base.py View Model:
a strictly horizontal collapsed row (arrow, hostname, (ip), then every immediate
action button), and an expanded TabbedContent whose first pane is Names (identity -
hostname, aliases, each with its provenance), labeled with the device's own current
hostname, followed by one tab per ResourceCategory with a matching service, then
Properties.
"""
from __future__ import annotations

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Collapsible, Input, Static, TabbedContent, TabPane

from ..core.actions import display_name as _display_name
from ..core.scanner import NetworkScanner
from .base import (
    DEFAULT_SAVE_PATH,
    NAMES_TAB_ID,
    PROPERTIES_TAB_ID,
    ActionView,
    CategoryTabView,
    DeviceRowView,
    ViewModelState,
    build_device_row_view,
    properties_section_ids,
    save_devices_to_json,
)

_EXPAND_ALL_LABEL = "Expand All"
_COLLAPSE_ALL_LABEL = "Collapse All"


def _static_with_tooltip(text: str, tooltip: str) -> Static:
    # tooltip isn't a Static constructor kwarg - it's set post-construction.
    static = Static(text, markup=False)
    static.tooltip = tooltip
    return static


def _add_action_button(action_view: ActionView) -> Button:
    # Text(...), not a bare string: Button has no markup=False escape hatch, and a
    # label built from external data (a share name, an instance name, ...) shouldn't
    # be interpreted as Rich markup just because it happens to contain "[...]".
    button = Button(Text(action_view.label))
    button.run_action = action_view.action
    return button


def _compose_form(action_view: ActionView, state: ViewModelState, cache_key: tuple) -> ComposeResult:
    cached = state.form_input_cache.get(cache_key, {})
    inputs = {}
    for field_name in action_view.fields:
        field_input = Input(
            value=cached.get(field_name, ""), placeholder=field_name, password=(field_name == "password"),
        )
        inputs[field_name] = field_input
        yield field_input
    submit = Button(Text(action_view.label))
    submit.form_submit = (action_view.action, inputs, cache_key)
    yield submit


class DeviceRow(Widget):
    """One device's row: collapsed (one horizontal line) or expanded (identity
    header + TabbedContent), matching ui/dpg.py's build_device_row exactly - the two
    frontends differ only in which toolkit calls draw the same DeviceRowView data."""

    def __init__(self, view: DeviceRowView, state: ViewModelState, scanner: NetworkScanner):
        super().__init__()
        self.view = view
        self.state = state
        self.scanner = scanner

    def _compose_overview_row(self) -> ComposeResult:
        """Every service's immediate, always-visible action. [View <Category>]
        buttons are the one way to reach a category tab before expanding."""
        for entry in self.view.overview:
            for action_view in entry.actions:
                yield _add_action_button(action_view)
            for category, label in entry.view_category_labels:
                button = Button(Text(label))
                button.is_view_category = True
                button.view_category = category
                yield button

    def _compose_category_tab(self, tab: CategoryTabView) -> ComposeResult:
        with TabPane(tab.category.value, id=f"tab-{tab.category.name}"):
            with VerticalScroll():
                for entry in tab.entries:
                    with Vertical():
                        yield Static(_display_name(entry.kind), markup=False)
                        if entry.status_text:
                            yield Static(f"  {entry.status_text}", markup=False)
                        if entry.fallback_label:
                            yield Static(f"  {entry.fallback_label}", markup=False)
                        for action_view in entry.actions:
                            if action_view.fields:
                                cache_key = (self.view.ip, entry.kind, tab.category)
                                yield from _compose_form(action_view, self.state, cache_key)
                            else:
                                yield _add_action_button(action_view)

    @staticmethod
    def _properties_section_id(section_id: str) -> str:
        return f"props-section-{section_id}"

    def _compose_properties_tab(self) -> ComposeResult:
        """Raw mDNS TXT records, one Collapsible section per service, defaulting to
        closed - this tab gets long, and Expand All/Collapse All (top right)
        toggles every section on this device at once (see on_button_pressed).
        Each section's open/closed state is tracked in self.state and reapplied
        via Collapsible(collapsed=...) on every rebuild, since Textual rebuilds
        every DeviceRow from scratch on each refresh; on_collapsible_expanded/
        collapsed (below) is what records a manual toggle before that happens.

        A service with nothing to show (no properties at all, or only
        blank-decoded keys) is skipped entirely, header included. Physical
        Devices only ever has anything to show for this machine's own row (see
        Device.physical_interfaces), so it's skipped just as completely for
        every other device."""
        section_ids = properties_section_ids(self.view.properties)
        all_expanded = self.state.all_properties_expanded(self.view.ip, section_ids)
        with TabPane("Properties", id="tab-properties"):
            with VerticalScroll():
                with Horizontal():
                    address = f"IP: {self.view.properties.ip}"
                    if self.view.properties.ipv6:
                        address += f"  /  {self.view.properties.ipv6}"
                    yield Static(address, markup=False)
                    toggle_button = Button(Text(_COLLAPSE_ALL_LABEL if all_expanded else _EXPAND_ALL_LABEL))
                    toggle_button.is_toggle_all_properties = True
                    yield toggle_button
                if self.view.properties.physical_devices:
                    with Collapsible(
                        title=Text("Physical Devices"), id=self._properties_section_id("physical_devices"),
                        collapsed=not self.state.is_properties_section_expanded(self.view.ip, "physical_devices"),
                    ):
                        for name, mac in self.view.properties.physical_devices:
                            yield Static(f"  {name} = {mac}", markup=False)
                for entry in self.view.properties.services:
                    properties = [(key, value) for key, value in entry.properties if key.strip()]
                    if not properties:
                        continue
                    with Collapsible(
                        title=Text(f"{entry.kind} (port {entry.port})"),
                        id=self._properties_section_id(entry.kind),
                        collapsed=not self.state.is_properties_section_expanded(self.view.ip, entry.kind),
                    ):
                        for key, value in properties:
                            yield Static(f"  {key} = {value}", markup=False)

    def _hostname_static(self) -> Static:
        sources = ", ".join(sorted(self.view.hostname_sources)) or "unknown"
        return _static_with_tooltip(self.view.hostname, f"Source: {sources}")

    def _compose_names_tab(self) -> ComposeResult:
        """The expanded view's first tab: identity (icon - not yet rendered in the
        TUI, hostname, aliases, each with its provenance), labeled with the
        device's own current hostname. About *which device this is*, not what you
        can do with it - actions live in the category tabs alongside this one."""
        with TabPane(self.view.hostname, id="tab-names"):
            yield self._hostname_static()
            for name, sources in sorted(self.view.names.aliases.items()):
                yield _static_with_tooltip(f"  {name}", ", ".join(sorted(sources)))

    def compose(self) -> ComposeResult:
        is_open = self.state.is_expanded(self.view.ip)
        toggle = Button("▼" if is_open else "▶")
        toggle.is_toggle = True

        if not is_open:
            with Horizontal():
                yield toggle
                yield self._hostname_static()
                yield Static(f"({self.view.ip})", markup=False)
                yield from self._compose_overview_row()
        else:
            valid_tab_ids = {NAMES_TAB_ID, PROPERTIES_TAB_ID} | {tab.category.name for tab in self.view.category_tabs}
            requested = self.state.get_active_tab(self.view.ip)
            target = requested if requested in valid_tab_ids else NAMES_TAB_ID
            with Vertical():
                yield toggle
                with TabbedContent(initial=f"tab-{target}"):
                    yield from self._compose_names_tab()
                    for tab in self.view.category_tabs:
                        yield from self._compose_category_tab(tab)
                    yield from self._compose_properties_tab()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Tracks whichever tab the user just switched to, so a later unrelated
        refresh (which fully rebuilds this row - there's no widget to just leave
        alone) lands back on that tab instead of silently resetting to Names. Also
        fires (harmlessly redundantly) from compose()'s own `initial=`, since
        that's a real tab activation too."""
        tab_id = event.tabbed_content.active.removeprefix("tab-")
        self.state.set_active_tab(self.view.ip, tab_id)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        button = event.button
        if getattr(button, "is_toggle", False):
            self.state.toggle_expanded(self.view.ip)
            await self.app.refresh_now()
        elif getattr(button, "is_view_category", False):
            self.state.expand(self.view.ip, category=button.view_category)
            await self.app.refresh_now()
        elif getattr(button, "is_toggle_all_properties", False):
            # Applies immediately to whatever's currently mounted (no rebuild
            # needed - unlike is_toggle/is_view_category above, nothing about
            # which resources exist changed) and updates self.state so a later
            # unrelated refresh_now() remembers it, the same idea as
            # on_collapsible_expanded/collapsed below.
            section_ids = properties_section_ids(self.view.properties)
            expand = not self.state.all_properties_expanded(self.view.ip, section_ids)
            for section_id in section_ids:
                self.state.set_properties_section_expanded(self.view.ip, section_id, expand)
            for collapsible in self.query(Collapsible):
                collapsible.collapsed = not expand
            button.label = Text(_COLLAPSE_ALL_LABEL if expand else _EXPAND_ALL_LABEL)
        elif hasattr(button, "form_submit"):
            action, inputs, cache_key = button.form_submit
            values = {name: field_input.value for name, field_input in inputs.items()}
            self.state.form_input_cache[cache_key] = values
            await action.run(self.scanner, **values)
        elif hasattr(button, "run_action"):
            await button.run_action.run(self.scanner)

    def on_collapsible_expanded(self, event: Collapsible.Expanded) -> None:
        """collapsing_header in DPG has no toggle callback at all; Textual's
        Collapsible does, just not named `Toggled` (that's an unused base class -
        the real messages are Expanded/Collapsed). Records a manual toggle before
        a later unrelated refresh_now() rebuilds this row from scratch and would
        otherwise silently reset it to collapsed."""
        event.stop()
        section_id = (event.collapsible.id or "").removeprefix("props-section-")
        self.state.set_properties_section_expanded(self.view.ip, section_id, True)

    def on_collapsible_collapsed(self, event: Collapsible.Collapsed) -> None:
        event.stop()
        section_id = (event.collapsible.id or "").removeprefix("props-section-")
        self.state.set_properties_section_expanded(self.view.ip, section_id, False)


class NetworkBrowserApp(App):
    """Textual entry point. Owns the AsyncNetworkScanner directly - no threading
    bridge needed, since Textual's own event loop *is* where the scanner runs."""

    CSS = """
    DeviceRow { height: auto; margin-bottom: 1; }
    TabbedContent { height: auto; max-height: 20; }
    Horizontal { height: auto; }
    /* Static defaults to filling its container's width (unlike Button, which is
       auto) - wrong for every use in this file, all of which are short inline
       labels sitting alongside buttons in a horizontal row. */
    Static { width: auto; }
    """

    def __init__(self, scanner: NetworkScanner | None = None):
        super().__init__()
        self.scanner = scanner if scanner is not None else NetworkScanner()
        self.view_state = ViewModelState()

    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="device-list")
        save_button = Button("Save")
        save_button.is_save = True
        yield save_button

    async def on_mount(self) -> None:
        await self.scanner.start()
        await self.refresh_now()
        self.set_interval(0.5, self._poll_refresh)

    async def _poll_refresh(self) -> None:
        if self.scanner.dirty:
            await self.refresh_now()

    async def refresh_now(self) -> None:
        self.scanner.dirty = False
        device_list = self.query_one("#device-list", VerticalScroll)
        await device_list.remove_children()
        rows = []
        for dev in list(self.scanner.devices.values()):
            expanded = self.view_state.is_expanded(dev.ip)
            view = await build_device_row_view(dev, self.scanner, expanded=expanded)
            rows.append(DeviceRow(view, self.view_state, self.scanner))
        if rows:
            await device_list.mount_all(rows)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Only ever sees the top-level Save button - every button inside a
        DeviceRow is handled (and the event stopped) by DeviceRow.on_button_pressed
        before it would otherwise bubble up this far."""
        if getattr(event.button, "is_save", False):
            event.stop()
            await self.save_devices()

    async def save_devices(self) -> None:
        """Writes every currently-known device's data to a JSON file, using each
        device's current expand-state (view_state.is_expanded) - the same
        lazy-load-respecting snapshot already on screen, not a forced full-expand
        of every device, which would trigger the eager, unprompted fetches lazy
        loading exists to prevent."""
        views = [
            await build_device_row_view(dev, self.scanner, expanded=self.view_state.is_expanded(dev.ip))
            for dev in list(self.scanner.devices.values())
        ]
        save_devices_to_json(views)
        self.notify(f"Saved {len(views)} device(s) to {DEFAULT_SAVE_PATH}")

    async def on_unmount(self) -> None:
        await self.scanner.close()


def main() -> None:
    NetworkBrowserApp().run()


if __name__ == "__main__":
    main()
