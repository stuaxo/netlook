"""Textual TUI frontend. Runs on the same asyncio event loop as the async core (no
threading bridge needed here, unlike ui/dpg.py) - this module can just `await`
scanner/action calls directly.

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
    LoginPromptView,
    ViewModelState,
    build_device_row_view,
    properties_section_ids,
    save_devices_to_json,
    submit_login,
)

_EXPAND_ALL_LABEL = "Expand All"
_COLLAPSE_ALL_LABEL = "Collapse All"


def _static_with_tooltip(text: str, tooltip: str) -> Static:
    # tooltip isn't a Static constructor kwarg - it's set post-construction.
    static = Static(text, markup=False)
    static.tooltip = tooltip
    return static


def _trim_button(button: Button) -> Button:
    """Zeroes out line-pad (the blank column Button reserves on each side of its
    label) so a compact/borderless button is genuinely single-height with no
    residual padding - can't be done via the `.toggle`/`.tag`/`.utility` CSS
    classes themselves (see NetworkBrowserApp.CSS), since this Textual version's
    CSS integer parser rejects a literal `line-pad: 0;`, even though 0 is the
    property's own default."""
    button.styles.line_pad = 0
    return button


def _add_action_button(action_view: ActionView, classes: str = "") -> Button:
    # Text(...), not a bare string: Button has no markup=False escape hatch, and a
    # label built from external data (a share name, an instance name, ...) shouldn't
    # be interpreted as Rich markup just because it happens to contain "[...]".
    button = Button(Text(action_view.label), classes=classes, compact=bool(classes))
    button.run_action = action_view.action
    return _trim_button(button) if classes else button


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


def _compose_login_form(login: LoginPromptView, state: ViewModelState, cache_key: tuple) -> ComposeResult:
    """Parallel to _compose_form, for a LoginPromptView instead of a form-backed
    ActionView - submits via submit_login (scanner.request_items) rather than
    action.run(), since a login prompt isn't an Action at all."""
    cached = state.form_input_cache.get(cache_key, {})
    inputs = {}
    for field_name in login.fields:
        field_input = Input(
            value=cached.get(field_name, ""), placeholder=field_name, password=(field_name == "password"),
        )
        inputs[field_name] = field_input
        yield field_input
    submit = Button(Text("sign in"))
    submit.login_submit = (login, inputs, cache_key)
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
        buttons are the one way to reach a category tab before expanding.

        Rendered as compact, borderless "tags" (see the .tag CSS classes below)
        rather than full-size buttons - actions in bold/primary, category links
        in dim/italic - so several of these sit inline on one line next to the
        hostname instead of each wrapping into its own blocky row."""
        for entry in self.view.overview:
            for action_view in entry.actions:
                yield _add_action_button(action_view, classes="tag tag-action")
            for category, label in entry.view_category_labels:
                button = _trim_button(Button(Text(label), classes="tag tag-link", compact=True))
                button.is_view_category = True
                button.view_category = category
                yield button

    def _compose_category_tab(self, tab: CategoryTabView) -> ComposeResult:
        with TabPane(tab.category.value, id=f"tab-{tab.category.name}"):
            with VerticalScroll(classes="tab-body"):
                for entry in tab.entries:
                    with Vertical():
                        yield Static(_display_name(entry.kind), markup=False)
                        if entry.status_text:
                            yield Static(f"  {entry.status_text}", markup=False)
                        if entry.fallback_label:
                            yield Static(f"  {entry.fallback_label}", markup=False)
                        if entry.login:
                            cache_key = (self.view.ip, entry.kind, tab.category)
                            yield from _compose_login_form(entry.login, self.state, cache_key)
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
            with VerticalScroll(classes="tab-body"):
                with Horizontal():
                    address = f"IP: {self.view.properties.ip}"
                    if self.view.properties.ipv6:
                        address += f"  /  {self.view.properties.ipv6}"
                    yield Static(address, markup=False)
                    toggle_button = _trim_button(Button(
                        Text(_COLLAPSE_ALL_LABEL if all_expanded else _EXPAND_ALL_LABEL),
                        classes="utility", compact=True,
                    ))
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
        toggle = _trim_button(Button("▼" if is_open else "▶", classes="toggle", compact=True))
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
                # Same header line as the collapsed row (arrow, hostname, ip) -
                # kept visible above the tabs instead of disappearing into just a
                # tab-strip label, so expanding never costs the user the context
                # of *which device* they're now looking at.
                with Horizontal():
                    yield toggle
                    yield self._hostname_static()
                    yield Static(f"({self.view.ip})", markup=False)
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

    def _scroll_into_view(self) -> None:
        """refresh_now() rebuilds every DeviceRow from scratch, so `self` is about
        to be torn down - looks up its replacement by ip and scrolls it into view
        immediately after, so expanding/collapsing keeps the row the user just
        clicked on-screen instead of leaving them to relocate it after everything
        below it shifts down (the inline-accordion behavior this app is going
        for, rather than a detail pane that yanks focus away from the list)."""
        ip = self.view.ip
        for row in self.app.query(DeviceRow):
            if row.view.ip == ip:
                row.scroll_visible(animate=False)
                break

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        button = event.button
        if getattr(button, "is_toggle", False):
            self.state.toggle_expanded(self.view.ip)
            await self.app.refresh_now()
            self._scroll_into_view()
        elif getattr(button, "is_view_category", False):
            self.state.expand(self.view.ip, category=button.view_category)
            await self.app.refresh_now()
            self._scroll_into_view()
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
        elif hasattr(button, "login_submit"):
            login, inputs, cache_key = button.login_submit
            values = {name: field_input.value for name, field_input in inputs.items()}
            self.state.form_input_cache[cache_key] = values
            await submit_login(self.scanner, login, **values)
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
    /* Vertical defaults to `height: 1fr` (fill whatever space its parent has
       left) - fine for a one-shot screen layout, but wrong anywhere inside a
       DeviceRow: both its own expanded-state wrapper (compose()) and each
       category-tab entry's wrapper (_compose_category_tab) used to balloon to
       fill all the way up to the nearest height cap regardless of actual
       content, shoving rows below off-screen and reading as a fixed pane
       rather than an inline accordion. A descendant selector, not just
       `DeviceRow > Vertical`, since the entry wrapper is nested several levels
       deeper (inside TabbedContent/ContentSwitcher/TabPane/VerticalScroll),
       not a direct child - auto sizes every one of them to real content
       instead, so later rows/entries just shift down underneath. */
    DeviceRow Vertical { height: auto; }
    TabbedContent { height: auto; max-height: 20; }
    Horizontal { height: auto; }
    /* Static defaults to filling its container's width (unlike Button, which is
       auto) - wrong for every use in this file, all of which are short inline
       labels sitting alongside buttons in a horizontal row. */
    Static { width: auto; }

    /* VerticalScroll (used for every tab body - see _compose_category_tab and
       _compose_properties_tab) defaults to `height: 1fr`, same problem as plain
       Vertical above but one level deeper: TabPane/ContentSwitcher are
       height:auto, and an auto-sized ancestor with a 1fr descendant gets
       stretched to fill all the way up to TabbedContent's own max-height cap -
       so even a device with two lines of content rendered as a ~20-row-tall
       box, eating the rest of the screen regardless of how little it actually
       had to show. .tab-body sizes to its real content instead, and only caps
       out (falling back to its own scrollbar) for a device that genuinely has
       more than max-height worth to show. Scoped to this class, not a blanket
       VerticalScroll rule, since #device-list (the outer, whole-app scroll
       region) still needs height:1fr to fill and scroll the real screen. */
    .tab-body { height: auto; max-height: 14; }

    /* The collapsed/expanded disclosure arrow: a bare glyph with no border,
       padding, or background so it reads as inline punctuation next to the
       hostname, not a blocky control competing with it for space. */
    /* line-pad (the blank column Button reserves on each side of its label)
       can't be zeroed here - Textual's CSS integer parser rejects a literal
       0 for line-pad in this version, even though 0 is the property's own
       default, so `_trim_button` (below) sets it back to 0 in Python instead
       for every class here. */
    .toggle {
        min-width: 3; width: 3; height: 1;
        border: none; padding: 0; background: transparent;
        color: $text-muted;
    }
    .toggle:hover { color: $text; text-style: bold; }

    /* Overview-row "tags" (immediate actions and [View <Category>] links):
       compact and borderless so several sit inline on one line with the
       hostname/ip, distinguished by color/weight instead of a background
       block that forces a line wrap. */
    .tag {
        min-width: 0; height: 1;
        border: none; padding: 0 1 0 0; background: transparent;
    }
    .tag:hover { text-style: bold underline; }
    .tag-action { color: $primary; text-style: bold; }
    .tag-link { color: $text-muted; text-style: italic; }

    /* Utility chrome (Save, Expand All/Collapse All) - present but visually
       recessive, so the device data stays the primary focus instead of
       competing with high-contrast button borders. */
    .utility {
        height: 1; min-width: 10;
        border: none; padding: 0 1; background: $panel; color: $text-muted;
    }
    .utility:hover { background: $boost; color: $text; }
    """

    def __init__(self, scanner: NetworkScanner | None = None):
        super().__init__()
        self.scanner = scanner if scanner is not None else NetworkScanner()
        self.view_state = ViewModelState()

    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="device-list")
        save_button = _trim_button(Button("Save", classes="utility", compact=True))
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
