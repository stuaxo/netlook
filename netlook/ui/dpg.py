"""DearPyGui presentation layer. The only module in the package allowed to
import dearpygui - everything in core/ and ui/base.py is toolkit-agnostic,
so a different frontend (ui/textual.py, a web UI, ...) could sit alongside
it without touching either.

DPG is strictly synchronous and must run on the main thread, but the core
(scanner.py) is asyncio-only, so CoreBridge runs it on its own background
thread with its own event loop. UI-triggered work (button clicks, form
submits) crosses into that loop via asyncio.run_coroutine_threadsafe. State
flows the other way through a thread-safe snapshot mailbox: the core thread
computes fresh DeviceRowViews (ui/base.py) and publishes them; this module's
render loop only reads the latest published list, never touching live
scanner/Device/Service state directly.

DearPyGui callbacks always arrive as (sender, app_data, user_data), with no
slot for extra arguments - so the one piece of module-level state here is
`_bridge`, set once by main(). Every non-callback function still takes the
bridge as an explicit parameter; only the callbacks DearPyGui itself invokes
fall back to the global, since they have no choice.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import threading

import dearpygui.dearpygui as dpg

from ..core.actions import Action, display_name
from ..core.models import ResourceCategory
from ..core.scanner import NetworkScanner
from ..dump import DEFAULT_SCAN_SECONDS, dump
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

# ----------------------------------------------------------------------------------
# Theme
# ----------------------------------------------------------------------------------

def _rgba(r: float, g: float, b: float, a: float = 1.0) -> tuple:
    # ImGui colors are 0.0-1.0 floats; dearpygui theme colors are 0-255 ints.
    return (round(r * 255), round(g * 255), round(b * 255), round(a * 255))


def _catppuccin_mocha_theme() -> int:
    """Catppuccin Mocha, ported from the ImGui C++ style-setup function - same nested
    theme()/theme_component() context managers already used for the per-item themes
    below, just building one theme bound globally instead of per-item."""
    with dpg.theme() as theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_style(dpg.mvStyleVar_WindowPadding, 12, 12, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 6, 4, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 8, 6, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_ScrollbarSize, 14, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_GrabMinSize, 12, category=dpg.mvThemeCat_Core)

            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 8, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 5, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_PopupRounding, 5, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 12, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 5, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 5, category=dpg.mvThemeCat_Core)

            dpg.add_theme_style(dpg.mvStyleVar_WindowBorderSize, 1, category=dpg.mvThemeCat_Core)
            dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 0, category=dpg.mvThemeCat_Core)  # minimalist look
            dpg.add_theme_style(dpg.mvStyleVar_PopupBorderSize, 1, category=dpg.mvThemeCat_Core)

            # Catppuccin Mocha: Base #1e1e2e, Mantle #181825, Crust #11111b, Text #cdd6f4,
            # Subtext0 #a6adc8, Surface0 #313244, Lavender #b4befe, Sapphire #74c7ec, Mauve #cba6f7
            dpg.add_theme_color(dpg.mvThemeCol_Text, _rgba(0.80, 0.84, 0.96), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, _rgba(0.42, 0.45, 0.55), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, _rgba(0.12, 0.12, 0.18), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ChildBg, _rgba(0.09, 0.09, 0.15), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_PopupBg, _rgba(0.07, 0.07, 0.11, 0.96), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_Border, _rgba(0.19, 0.20, 0.27), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_BorderShadow, _rgba(0, 0, 0, 0), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, _rgba(0.19, 0.20, 0.27), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, _rgba(0.25, 0.26, 0.35), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, _rgba(0.31, 0.32, 0.42), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_TitleBg, _rgba(0.09, 0.09, 0.15), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, _rgba(0.12, 0.12, 0.18), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, _rgba(0.07, 0.07, 0.11), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_MenuBarBg, _rgba(0.09, 0.09, 0.15), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, _rgba(0.09, 0.09, 0.15), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, _rgba(0.31, 0.32, 0.42), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, _rgba(0.37, 0.38, 0.51),
                                 category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, _rgba(0.42, 0.45, 0.55),
                                 category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_CheckMark, _rgba(0.71, 0.75, 1.00), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, _rgba(0.45, 0.78, 0.93), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, _rgba(0.45, 0.78, 0.93),
                                 category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_Button, _rgba(0.19, 0.20, 0.27), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, _rgba(0.80, 0.65, 0.97), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, _rgba(0.70, 0.55, 0.87), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_Header, _rgba(0.19, 0.20, 0.27), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, _rgba(0.25, 0.26, 0.35), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, _rgba(0.31, 0.32, 0.42), category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_Tab, _rgba(0.12, 0.12, 0.18), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TabHovered, _rgba(0.31, 0.32, 0.42), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TabActive, _rgba(0.19, 0.20, 0.27), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocused, _rgba(0.09, 0.09, 0.15), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocusedActive, _rgba(0.12, 0.12, 0.18),
                                 category=dpg.mvThemeCat_Core)

            dpg.add_theme_color(dpg.mvThemeCol_PlotLines, _rgba(0.94, 0.72, 0.42), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_TextSelectedBg, _rgba(0.31, 0.32, 0.42), category=dpg.mvThemeCat_Core)
            dpg.add_theme_color(dpg.mvThemeCol_NavHighlight, _rgba(0.71, 0.75, 1.00), category=dpg.mvThemeCat_Core)

            if hasattr(dpg, "mvThemeCol_DockingPreview"):
                dpg.add_theme_color(dpg.mvThemeCol_DockingPreview, _rgba(0.71, 0.75, 1.00, 0.50),
                                     category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_DockingEmptyBg, _rgba(0.12, 0.12, 0.18),
                                     category=dpg.mvThemeCat_Core)

    return theme


_error_theme = None


def _get_error_theme():
    global _error_theme
    if _error_theme is None:
        with dpg.theme() as _error_theme:
            with dpg.theme_component(dpg.mvInputText):
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (80, 20, 20), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Border, (200, 60, 60), category=dpg.mvThemeCat_Core)
                dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 1, category=dpg.mvThemeCat_Core)
    return _error_theme


# icon_path -> (texture tag, width, height), or None for a path that failed to load
_icon_textures: dict = {}


def _get_icon_texture(icon_path: str):
    if icon_path not in _icon_textures:
        try:
            width, height, _channels, data = dpg.load_image(icon_path)
            with dpg.texture_registry():
                texture = dpg.add_static_texture(width, height, data)
            _icon_textures[icon_path] = (texture, width, height)
        except Exception:
            _icon_textures[icon_path] = None
    return _icon_textures[icon_path]


# Visual hierarchy for device identity: a bright/bold-weight primary hostname, with
# any other discovered names underneath in a smaller, muted secondary style.
_hostname_theme = None
_alias_theme = None


def _get_hostname_theme():
    global _hostname_theme
    if _hostname_theme is None:
        with dpg.theme() as _hostname_theme:
            with dpg.theme_component(dpg.mvText):
                dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
    return _hostname_theme


def _get_alias_theme():
    global _alias_theme
    if _alias_theme is None:
        with dpg.theme() as _alias_theme:
            with dpg.theme_component(dpg.mvText):
                dpg.add_theme_color(dpg.mvThemeCol_Text, (130, 130, 130), category=dpg.mvThemeCat_Core)
    return _alias_theme


def _add_name_with_tooltip(text: str, sources: set[str], theme) -> None:
    item = dpg.add_text(text)
    dpg.bind_item_theme(item, theme)
    with dpg.tooltip(item):
        label = "Source" if len(sources) == 1 else "Sources"
        dpg.add_text(f"{label}: {', '.join(sorted(sources)) if sources else 'unknown'}")


def _format_sources_badge(sources: set[str]) -> str:
    return f"[{', '.join(sorted(sources))}]" if sources else "[unknown]"


def _invisible_grid():
    """A two-column dpg.table with every grid line disabled - structural
    alignment (a fixed-width label/source column, a stretching value/name
    column) with no visible table chrome. Caller must add the column pair
    (_add_grid_columns) first, then rows via `with dpg.table_row():`. Must
    not be used as the direct parent of a spacer or anything else that
    isn't a row/column - DPG only accepts mvTableRow/mvTableColumn as a
    table's direct children."""
    return dpg.table(header_row=False, borders_innerH=False, borders_innerV=False,
                      borders_outerH=False, borders_outerV=False)


_GRID_LABEL_WIDTH = 140


def _add_grid_columns(label_width: int = _GRID_LABEL_WIDTH) -> None:
    dpg.add_table_column(width_fixed=True, init_width_or_weight=label_width)
    dpg.add_table_column()


_right_aligned_key_theme = None


def _get_right_aligned_key_theme():
    """Right-aligns via ImGui's native SelectableTextAlign style var rather
    than a manually measured indent, so alignment is computed by the
    renderer from the current font/DPI every frame instead of a one-off
    get_text_size() estimate. Selection highlighting is disabled since
    these labels aren't interactive."""
    global _right_aligned_key_theme
    if _right_aligned_key_theme is None:
        with dpg.theme() as _right_aligned_key_theme:
            with dpg.theme_component(dpg.mvSelectable):
                dpg.add_theme_style(dpg.mvStyleVar_SelectableTextAlign, 1.0, 0.5, category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Header, (0, 0, 0, 0), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, (0, 0, 0, 0), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, (0, 0, 0, 0), category=dpg.mvThemeCat_Core)
    return _right_aligned_key_theme


def _add_right_aligned_text(text: str):
    """A selectable styled as plain, bright, right-aligned text - a table-column
    selectable naturally fills its column's width, giving SelectableTextAlign room
    to push the label against the value column's edge without any manual sizing."""
    item = dpg.add_selectable(label=text)
    dpg.bind_item_theme(item, _get_right_aligned_key_theme())
    return item


def _add_selectable_value(value: str, width: int = -1):
    """A read-only input field standing in for plain text wherever a
    displayed value (a TXT record's value, an IP address, ...) might need
    copying - unlike dpg.add_text, InputText natively supports click-drag
    selection and Ctrl+C. auto_select_all means a single click selects the
    whole value, ready to copy, rather than requiring a drag across it.
    width=-1 (default) fills the available column width."""
    return dpg.add_input_text(default_value=value, readonly=True, width=width, auto_select_all=True)


# Fixed, not content-measured: an input box's width doesn't shrink to its own text
# the way a button's does, so there's no native "fit this value" mechanism to lean
# on here - these are simply wide enough for the longest realistic value of each
# kind (IPv4 vs. IPv6 address).
_IPV4_VALUE_WIDTH = 140
_IPV6_VALUE_WIDTH = 260


# ----------------------------------------------------------------------------------
# Window/table scaffolding
# ----------------------------------------------------------------------------------

# DearPyGui's bundled default font only covers basic Latin, so symbols like the
# disclosure triangles (▶/▼) render as blank glyphs unless a broader-coverage font is
# bound. DejaVu Sans is present on nearly every Linux desktop - checked in likelihood
# order, falling back to whatever the default font already covers if truly none of
# these are installed (the app still works, just without those glyphs rendering).
_UNICODE_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
]


def _bind_unicode_font() -> None:
    for path in _UNICODE_FONT_CANDIDATES:
        if not os.path.exists(path):
            continue
        with dpg.font_registry():
            with dpg.font(path, 16) as font:
                pass
        dpg.bind_font(font)
        return


def _on_escape_key(sender, app_data) -> None:
    dpg.stop_dearpygui()


def build_ui():
    dpg.create_context()
    _bind_unicode_font()
    dpg.bind_theme(_catppuccin_mocha_theme())
    with dpg.handler_registry():
        dpg.add_key_press_handler(dpg.mvKey_Escape, callback=_on_escape_key)
    # Primary (not just a plain window): fills the viewport as the app's own main
    # surface instead of floating inside it as a separate, title-barred, collapsible
    # child - there's only ever one window here, so a viewport-within-a-viewport
    # look (drag handle, collapse arrow, its own border) is chrome with nothing to
    # manage, not a real second surface.
    with dpg.window(tag="main_window"):
        # header_row=False + a narrow unlabeled first column: a plain left-hand
        # gutter for the disclosure arrow, sitting right next to each device's name
        # in the wide second column.
        with dpg.table(header_row=False, tag="device_list", borders_innerH=True):
            dpg.add_table_column(width_fixed=True, init_width_or_weight=24)
            dpg.add_table_column()

        with dpg.group(horizontal=True):
            dpg.add_button(label="Save", callback=_on_save_click)
            dpg.add_text("", tag="save_status")

    dpg.create_viewport(title="Local Network Browser", width=600, height=400)
    dpg.setup_dearpygui()
    dpg.set_primary_window("main_window", True)
    dpg.show_viewport()


# ----------------------------------------------------------------------------------
# CoreBridge: the threading<->asyncio boundary
# ----------------------------------------------------------------------------------

class CoreBridge:
    """Owns the async core on its own background thread/event loop.

    Cross-thread state is deliberately narrow: which device ips are
    expanded (the DPG thread writes, the core thread reads - it needs to
    know before deciding whether building category_tabs, and the fetches
    that can trigger, is warranted; see build_device_row_view's docstring)
    and the latest published DeviceRowView snapshot (the core thread
    writes, the DPG thread reads)."""

    def __init__(self, scanner_factory=NetworkScanner):
        self._scanner_factory = scanner_factory
        self._lock = threading.Lock()
        self._expanded_ips: set[str] = set()
        self._version = 0
        self._latest_views: list[DeviceRowView] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.scanner: NetworkScanner | None = None

    def start(self) -> None:
        ready = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(ready,), daemon=True, name="CoreLoop")
        self._thread.start()
        ready.wait()

    def _run(self, ready: threading.Event) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self.scanner = self._scanner_factory()
        ready.set()
        try:
            self._loop.run_until_complete(self._main())
        finally:
            self._loop.close()

    async def _main(self) -> None:
        await self.scanner.start()
        try:
            while not self._stop_event.is_set():
                if self.scanner.dirty:
                    self.scanner.dirty = False
                    await self._publish()
                await asyncio.sleep(0.1)
        finally:
            await self.scanner.close()

    async def _publish(self) -> None:
        with self._lock:
            expanded_ips = set(self._expanded_ips)
        views = [
            await build_device_row_view(dev, self.scanner, expanded=(dev.ip in expanded_ips))
            for dev in list(self.scanner.devices.values())
        ]
        with self._lock:
            self._latest_views = views
            self._version += 1

    def is_expanded(self, ip: str) -> bool:
        with self._lock:
            return ip in self._expanded_ips

    def toggle_expanded(self, ip: str) -> None:
        with self._lock:
            if ip in self._expanded_ips:
                self._expanded_ips.discard(ip)
            else:
                self._expanded_ips.add(ip)
        self.request_refresh()

    def expand(self, ip: str) -> None:
        """Unlike toggle_expanded, never collapses an already-open row - for a
        [View <Category>] button, which should only ever open, never accidentally
        close a row the user is already looking at."""
        with self._lock:
            self._expanded_ips.add(ip)
        self.request_refresh()

    def request_refresh(self) -> None:
        """Forces the core thread to republish on its next poll tick (up to ~0.1s
        away) instead of waiting for unrelated scanner activity to mark it dirty -
        so expanding/collapsing a row feels immediate."""
        if self._loop:
            self._loop.call_soon_threadsafe(self._mark_dirty)

    def _mark_dirty(self) -> None:
        if self.scanner:
            self.scanner.dirty = True

    def read_snapshot(self) -> tuple[int, list[DeviceRowView]]:
        with self._lock:
            return self._version, self._latest_views

    def run_coroutine(self, coro) -> None:
        """Fire-and-forget: submit a coroutine (an Action.run(...) call) to run on
        the core's event loop from the DPG main thread."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        future.add_done_callback(_log_if_failed)

    def stop(self) -> None:
        self._stop_event.set()
        self.request_refresh()  # wakes the poll loop out of its sleep(0.1) promptly
        if self._thread:
            self._thread.join(timeout=5)


def _log_if_failed(future: "asyncio.Future") -> None:
    if future.cancelled():
        return
    exc = future.exception()
    if exc is not None:
        print(f"Action failed: {exc!r}")


# ----------------------------------------------------------------------------------
# Interaction state and callbacks
#
# DearPyGui invokes callbacks as (sender, app_data, user_data), with no room for an
# extra bridge argument - `_bridge` (set once by main()) is how they reach it.
# ----------------------------------------------------------------------------------

# (ip, service kind, category) -> {field name: value}, preserved across rebuilds
# triggered by unrelated network activity (only the affected row gets wiped and
# rebuilt now - see refresh_table - but a row mid-rebuild still loses its own live
# widgets). Purely DPG-thread-local - forms are only ever read/written here, so
# unlike expand state this never needs to cross the thread boundary.
_view_state = ViewModelState()
# The most recently rendered snapshot, kept so _snapshot_form_inputs (called just
# before the *next* rebuild replaces it) knows which form tags might still exist,
# and so refresh_table can diff against it to find which rows actually changed.
_last_rendered_views: list[DeviceRowView] = []
# ips rendered expanded as of _last_rendered_views - expand/collapse alone doesn't
# always change a DeviceRowView's own fields (a device with no expandable category
# still renders differently expanded vs. collapsed - see refresh_table), so it's
# tracked as its own diff input rather than folded into DeviceRowView itself, which
# has no business knowing about per-frontend UI state (see ViewModelState).
_last_rendered_expanded: set[str] = set()
_bridge: CoreBridge | None = None


def _field_tag(kind: str, ip: str, field_name: str, category: ResourceCategory | None) -> str:
    return f"{kind}_{field_name}::{ip}::{category.name if category else 'summary'}"


def _snapshot_fields(dev_view: DeviceRowView, kind: str, category: ResourceCategory | None,
                      fields: tuple[str, ...]) -> None:
    """Shared by _snapshot_form_inputs for both an ActionView's fields and a
    LoginPromptView's - same tag scheme, same cache key, just a different source
    of field names."""
    tags = {name: _field_tag(kind, dev_view.ip, name, category) for name in fields}
    values = {name: dpg.get_value(tag) for name, tag in tags.items() if dpg.does_item_exist(tag)}
    if values:
        _view_state.form_input_cache[(dev_view.ip, kind, category)] = values


def _snapshot_form_inputs() -> None:
    for dev_view in _last_rendered_views:
        for tab in dev_view.category_tabs:
            for entry in tab.entries:
                for action_view in entry.actions:
                    _snapshot_fields(dev_view, entry.kind, tab.category, action_view.fields)
                if entry.login:
                    _snapshot_fields(dev_view, entry.kind, tab.category, entry.login.fields)


def _snapshot_properties_expanded() -> None:
    """Reads each Properties section's current open/closed state before the next
    rebuild deletes it - collapsing_header has no callback of its own to hook, so
    this is how a manual toggle survives a later unrelated refresh, the same
    reason _snapshot_form_inputs exists for form fields."""
    for dev_view in _last_rendered_views:
        for section_id in properties_section_ids(dev_view.properties):
            tag = _properties_section_tag(dev_view.ip, section_id)
            if dpg.does_item_exist(tag):
                _view_state.set_properties_section_expanded(dev_view.ip, section_id, dpg.get_value(tag))


def _on_device_toggle_click(sender, app_data, ip: str):
    _bridge.toggle_expanded(ip)


def _on_save_click(sender, app_data, user_data):
    """Writes every currently-known device's data to a JSON file - whatever's
    in _last_rendered_views, the same snapshot already on screen, not a
    fresh forced-expand that would trigger the eager, unprompted fetches
    (e.g. anonymous SMB auth against every device) lazy loading exists to
    prevent."""
    save_devices_to_json(_last_rendered_views)
    dpg.set_value("save_status", f"Saved {len(_last_rendered_views)} device(s) to {DEFAULT_SAVE_PATH}")


def _on_view_category_click(sender, app_data, user_data):
    ip, category = user_data
    # active_tab is DPG-thread-local (see _view_state) so it's set directly, not
    # through the bridge - only "is this row expanded at all" needs to cross into
    # the core thread, since that's what gates building category_tabs.
    _view_state.set_active_tab(ip, category.name)
    _bridge.expand(ip)


def _tab_tag(ip: str, tab_id: str) -> str:
    return f"tab::{ip}::{tab_id}"


def _on_tab_changed(sender, app_data, ip: str):
    """Fires whenever the active tab changes for one device's tab_bar - both
    from a user click and from build_device_row's own dpg.set_value call
    enforcing a requested tab (harmlessly redundant there: it re-records the
    same value). Recording it here makes a manual tab switch "stick" across
    a later refresh, which would otherwise rebuild this row and land back
    on Names."""
    tab_id = app_data.removeprefix(f"tab::{ip}::")
    _view_state.set_active_tab(ip, tab_id)


def _on_action_click(sender, app_data, action: Action):
    _bridge.run_coroutine(action.run(_bridge.scanner))


def _on_form_submit(sender, app_data, user_data):
    action, tags = user_data
    kwargs = {name: dpg.get_value(tag) for name, tag in tags.items()}
    _bridge.run_coroutine(action.run(_bridge.scanner, **kwargs))


def _add_form(ip: str, kind: str, category: ResourceCategory | None, action_view: ActionView):
    cached = _view_state.form_input_cache.get((ip, kind, category), {})
    tags = {name: _field_tag(kind, ip, name, category) for name in action_view.fields}
    submit_data = (action_view.action, tags)
    for name, tag in tags.items():
        dpg.add_input_text(label=name, tag=tag, width=140, password=(name == "password"),
                            default_value=cached.get(name, ""), on_enter=True,
                            callback=_on_form_submit, user_data=submit_data)
    dpg.add_button(label=action_view.label, small=True, callback=_on_form_submit, user_data=submit_data)


def _add_action(ip: str, kind: str, category: ResourceCategory | None, action_view: ActionView):
    if action_view.fields:
        _add_form(ip, kind, category, action_view)
    else:
        dpg.add_button(label=action_view.label, small=True, callback=_on_action_click, user_data=action_view.action)


def _on_login_submit(sender, app_data, user_data):
    login, tags = user_data
    kwargs = {name: dpg.get_value(tag) for name, tag in tags.items()}
    _bridge.run_coroutine(submit_login(_bridge.scanner, login, **kwargs))


def _add_login_form(ip: str, kind: str, category: ResourceCategory | None, login: LoginPromptView):
    """Parallel to _add_form, for a LoginPromptView instead of a form-backed
    ActionView - submits via submit_login (scanner.request_items) rather than
    action.run(), since a login prompt isn't an Action at all."""
    cached = _view_state.form_input_cache.get((ip, kind, category), {})
    tags = {name: _field_tag(kind, ip, name, category) for name in login.fields}
    submit_data = (login, tags)
    for name, tag in tags.items():
        dpg.add_input_text(label=name, tag=tag, width=140, password=(name == "password"),
                            default_value=cached.get(name, ""), on_enter=True,
                            callback=_on_login_submit, user_data=submit_data)
    if login.failed and "password" in tags:
        dpg.bind_item_theme(tags["password"], _get_error_theme())
        with dpg.tooltip(tags["password"]):
            dpg.add_text("Sign-in failed - check username/password")
    dpg.add_button(label="sign in", small=True, callback=_on_login_submit, user_data=submit_data)


def _add_overview_row(dev_view: DeviceRowView):
    """Every service's immediate, always-visible action - buttons only, no plain-text
    labels, so this reads as one flowing action row. [View <Category>] buttons are
    the one way to reach a category tab before expanding."""
    for entry in dev_view.overview:
        for action_view in entry.actions:
            _add_action(dev_view.ip, entry.kind, None, action_view)
        for category, label in entry.view_category_labels:
            dpg.add_button(label=label, small=True, callback=_on_view_category_click,
                            user_data=(dev_view.ip, category))


def _add_category_tab(dev_view: DeviceRowView, tab: CategoryTabView):
    with dpg.tab(label=tab.category.value, tag=_tab_tag(dev_view.ip, tab.category.name)):
        for entry in tab.entries:
            with dpg.group():
                dpg.add_text(display_name(entry.kind))
                if entry.status_text:
                    dpg.add_text(f"  {entry.status_text}")
                if entry.fallback_label:
                    dpg.add_text(f"  {entry.fallback_label}")
                if entry.login:
                    _add_login_form(dev_view.ip, entry.kind, tab.category, entry.login)
                for action_view in entry.actions:
                    _add_action(dev_view.ip, entry.kind, tab.category, action_view)


def _add_key_value_grid(rows: list[tuple[str, str]]) -> None:
    """An invisible-grid block of right-aligned bold keys and selectable values -
    shared by the Properties tab's per-service TXT record blocks and its Physical
    Devices section, which are visually and structurally identical."""
    with _invisible_grid():
        _add_grid_columns()
        for key, value in rows:
            with dpg.table_row():
                _add_right_aligned_text(f"{key}:")
                _add_selectable_value(value)


def _properties_section_tag(ip: str, section_id: str) -> str:
    return f"props_section::{ip}::{section_id}"


_EXPAND_ALL_LABEL = "Expand All"
_COLLAPSE_ALL_LABEL = "Collapse All"


def _on_toggle_all_properties_click(sender, app_data, user_data):
    """collapsing_header has no callback, but does support get_value/set_value
    like a bool-valued widget, so this applies directly to what's on screen
    instead of forcing a rebuild, and updates _view_state so a later refresh
    remembers it. Reconfigures `sender` (the button itself) so its
    label/next action flips immediately too."""
    ip, section_ids, expand = user_data
    for section_id in section_ids:
        tag = _properties_section_tag(ip, section_id)
        if dpg.does_item_exist(tag):
            dpg.set_value(tag, expand)
        _view_state.set_properties_section_expanded(ip, section_id, expand)
    dpg.configure_item(sender, label=_COLLAPSE_ALL_LABEL if expand else _EXPAND_ALL_LABEL,
                        user_data=(ip, section_ids, not expand))


def _add_properties_tab(dev_view: DeviceRowView):
    """Raw mDNS TXT records, one collapsing section per service, defaulting
    to closed - this tab gets long, and Expand All/Collapse All (top right)
    toggles every section at once.

    Each section's open/closed state is tracked in _view_state and
    reapplied via default_open on every rebuild, since collapsing_header
    has no callback to hook (see _snapshot_properties_expanded).

    A service with nothing to show (no properties, or only blank-decoded
    keys) is skipped entirely, header included. Physical Devices only has
    anything to show for this machine's own row (see
    Device.physical_interfaces), so it's skipped for every other device.
    Finders always renders - Not Found is exactly as informative as
    Found."""
    section_ids = properties_section_ids(dev_view.properties)
    shown_services = []
    for entry in dev_view.properties.services:
        properties = [(key, value) for key, value in entry.properties if key.strip()]
        if properties:
            shown_services.append((entry, properties))
    with dpg.tab(label="Properties", tag=_tab_tag(dev_view.ip, PROPERTIES_TAB_ID)):
        dpg.add_text("IPs")
        with dpg.table(header_row=False, borders_innerH=False, borders_innerV=False,
                        borders_outerH=False, borders_outerV=False):
            dpg.add_table_column()
            dpg.add_table_column(width_fixed=True)  # auto-sized to the button's own label
            with dpg.table_row():
                with dpg.group(horizontal=True):
                    dpg.add_text("IPv4:")
                    _add_selectable_value(dev_view.properties.ip, width=_IPV4_VALUE_WIDTH)
                    if dev_view.properties.ipv6:
                        dpg.add_text("IPv6:")
                        _add_selectable_value(dev_view.properties.ipv6, width=_IPV6_VALUE_WIDTH)
                all_expanded = _view_state.all_properties_expanded(dev_view.ip, section_ids)
                dpg.add_button(
                    label=_COLLAPSE_ALL_LABEL if all_expanded else _EXPAND_ALL_LABEL, small=True,
                    callback=_on_toggle_all_properties_click,
                    user_data=(dev_view.ip, section_ids, not all_expanded),
                )

        dpg.add_spacer(height=8)
        dpg.add_separator()
        dpg.add_spacer(height=8)
        dpg.add_text("Data Sources")
        with dpg.collapsing_header(
            label="Finders", tag=_properties_section_tag(dev_view.ip, "finders"),
            default_open=_view_state.is_properties_section_expanded(dev_view.ip, "finders"),
        ):
            _add_key_value_grid([
                (finder.label, "Found" if finder.found else "Not Found")
                for finder in dev_view.properties.finders
            ])

        if dev_view.properties.physical_devices:
            dpg.add_spacer(height=8)
            with dpg.collapsing_header(
                label="Physical Devices", tag=_properties_section_tag(dev_view.ip, "physical_devices"),
                default_open=_view_state.is_properties_section_expanded(dev_view.ip, "physical_devices"),
            ):
                _add_key_value_grid(dev_view.properties.physical_devices)

        if shown_services:
            dpg.add_spacer(height=8)
            dpg.add_separator()
            dpg.add_spacer(height=8)
            dpg.add_text("mDNS")
            for i, (entry, properties) in enumerate(shown_services):
                if i > 0:
                    dpg.add_spacer(height=8)
                with dpg.collapsing_header(
                    label=f"{entry.kind} (port {entry.port})", tag=_properties_section_tag(dev_view.ip, entry.kind),
                    default_open=_view_state.is_properties_section_expanded(dev_view.ip, entry.kind),
                ):
                    _add_key_value_grid(properties)


def _add_identity_line(dev_view: DeviceRowView) -> None:
    """Icon + hostname (with tooltip) - the compact view's leftmost segment. No
    aliases here: the collapsed row stays to one line, so provenance detail is
    deferred to the expanded view's Names tab instead."""
    icon = _get_icon_texture(dev_view.icon_path) if dev_view.icon_path else None
    if icon:
        texture, width, height = icon
        dpg.add_image(texture, width=16, height=16)
    _add_name_with_tooltip(dev_view.hostname, dev_view.hostname_sources, _get_hostname_theme())


def _add_names_tab(dev_view: DeviceRowView):
    """The expanded view's first tab: identity (icon, hostname, aliases),
    labeled with the device's current hostname. About which device this is,
    not what you can do with it - actions live in the category tabs
    alongside this one.

    Provenance (which discovery source reported a name) is a visible
    left-column badge, not a hover tooltip - a grid, not a flat list, so the
    reader never has to hover to see where a name came from. The hostname
    row's name gets the bright/bold theme, alias rows stay muted, matching
    the collapsed row's icon+hostname line."""
    with dpg.tab(label=dev_view.hostname, tag=_tab_tag(dev_view.ip, NAMES_TAB_ID)):
        names = dev_view.names
        with _invisible_grid():
            _add_grid_columns()
            with dpg.table_row():
                source_item = dpg.add_text(_format_sources_badge(names.hostname_sources))
                dpg.bind_item_theme(source_item, _get_alias_theme())
                with dpg.group(horizontal=True):
                    icon = _get_icon_texture(names.icon_path) if names.icon_path else None
                    if icon:
                        texture, width, height = icon
                        dpg.add_image(texture, width=16, height=16)
                    name_item = dpg.add_text(names.hostname)
                    dpg.bind_item_theme(name_item, _get_hostname_theme())
            for name, sources in sorted(names.aliases.items()):
                with dpg.table_row():
                    source_item = dpg.add_text(_format_sources_badge(sources))
                    dpg.bind_item_theme(source_item, _get_alias_theme())
                    name_item = dpg.add_text(name)
                    dpg.bind_item_theme(name_item, _get_alias_theme())


def _row_tag(ip: str) -> str:
    return f"device_row::{ip}"


def build_device_row(dev_view: DeviceRowView, bridge: CoreBridge, before: int | str = 0) -> None:
    """The whole per-device row: a disclosure arrow in the table's narrow
    first column, sitting left of the device's name, and everything else in
    the wide second column.

    Collapsed (the default): one horizontal line - icon, hostname, (IP),
    then every service's immediate action buttons. Cheap to draw and
    triggers no fetches.

    Expanded: a dpg.tab_bar. Its first tab is Names (see _add_names_tab),
    then one tab per ResourceCategory with a matching service on this
    device (in definition order), then Properties last, dumping every
    service's raw mDNS TXT records. Which tab is active is enforced after
    building all of them, from _view_state.active_tab - either a category
    requested via a [View <Category>] button, or whichever tab the user
    last switched to manually (see _on_tab_changed); defaults to Names.

    Reads entirely from dev_view (ui/base.py's DeviceRowView) - never
    touches a live Device/Service, since those live on the core thread.
    Tagged with _row_tag(ip) and placed at `before` (another row's tag, or
    0 to append) so refresh_table can delete and reinsert just this one row
    in place instead of the whole table."""
    is_open = bridge.is_expanded(dev_view.ip)
    with dpg.table_row(parent="device_list", tag=_row_tag(dev_view.ip), before=before):
        dpg.add_button(label="▼" if is_open else "▶", small=True,
                        callback=_on_device_toggle_click, user_data=dev_view.ip)
        with dpg.group():
            if not is_open:
                with dpg.group(horizontal=True):
                    _add_identity_line(dev_view)
                    dpg.add_text(f"({dev_view.ip})")
                    _add_overview_row(dev_view)
            else:
                tab_bar_tag = f"tab_bar::{dev_view.ip}"
                with dpg.tab_bar(tag=tab_bar_tag, callback=_on_tab_changed, user_data=dev_view.ip):
                    _add_names_tab(dev_view)
                    valid_tab_ids = {NAMES_TAB_ID, PROPERTIES_TAB_ID}
                    for tab in dev_view.category_tabs:
                        _add_category_tab(dev_view, tab)
                        valid_tab_ids.add(tab.category.name)
                    _add_properties_tab(dev_view)
                # Enforce the requested/remembered active tab now that every tab
                # actually exists to select - falls back to Names if the request
                # names a category this device no longer has (e.g. a service
                # disappeared), rather than crashing set_value on a stale tag.
                requested = _view_state.get_active_tab(dev_view.ip)
                target = requested if requested in valid_tab_ids else NAMES_TAB_ID
                dpg.set_value(tab_bar_tag, _tab_tag(dev_view.ip, target))


def refresh_table(bridge: CoreBridge) -> None:
    """Rebuilds only the rows whose rendered content actually changed since
    the last publish, not the whole device_list. scanner.dirty (see
    scanner.py) flips on any background discovery activity anywhere on the
    network, not just the device a user is looking at, so rebuilding every
    row on every tick used to tear down whatever row was expanded or
    mid-login far more often than its content actually changed - losing
    focus, tab-hover, and other transient DPG widget state, which read as
    flicker.

    Devices are only ever appended to NetworkScanner.devices, never
    reordered or removed (see scanner.py), so an unchanged row's position
    never needs to move. Walking `views` back-to-front and reinserting only
    changed/new rows `before` the next row's tag works because, by
    induction, that next row is already at its correct final position:
    either untouched, or already rebuilt there itself earlier in this same
    backward pass."""
    global _last_rendered_views, _last_rendered_expanded
    version, views = bridge.read_snapshot()
    if version == refresh_table.last_version:
        return
    refresh_table.last_version = version

    _snapshot_form_inputs()
    _snapshot_properties_expanded()

    old_by_ip = {v.ip: v for v in _last_rendered_views}
    new_ips = {v.ip for v in views}
    for stale_ip in old_by_ip.keys() - new_ips:
        tag = _row_tag(stale_ip)
        if dpg.does_item_exist(tag):
            dpg.delete_item(tag)

    expanded_now: dict[str, bool] = {}
    for i in range(len(views) - 1, -1, -1):
        dev_view = views[i]
        is_open = bridge.is_expanded(dev_view.ip)
        expanded_now[dev_view.ip] = is_open
        # A device with no expandable category renders identically whether "open" or
        # not, aside from the disclosure arrow, so DeviceRowView equality alone can't
        # be trusted to catch every expand/collapse - is_open has to be compared too.
        if dev_view == old_by_ip.get(dev_view.ip) and is_open == (dev_view.ip in _last_rendered_expanded):
            continue
        tag = _row_tag(dev_view.ip)
        if dpg.does_item_exist(tag):
            dpg.delete_item(tag)
        before = _row_tag(views[i + 1].ip) if i + 1 < len(views) else 0
        build_device_row(dev_view, bridge, before=before)

    _last_rendered_views = views
    _last_rendered_expanded = {ip for ip, open_ in expanded_now.items() if open_}


refresh_table.last_version = -1


def run(bridge: CoreBridge) -> None:
    """Build the window and drive the frame loop until the user closes it."""
    global _bridge
    _bridge = bridge
    build_ui()
    try:
        while dpg.is_dearpygui_running():
            refresh_table(bridge)
            dpg.render_dearpygui_frame()
    finally:
        bridge.stop()
        dpg.destroy_context()


def main() -> None:
    parser = argparse.ArgumentParser(prog="netlook", description="Local network device browser.")
    parser.add_argument("--dump", action="store_true",
                         help="Scan the network, fetch everything discoverable, and print/write it "
                              "as JSON - no GUI.")
    parser.add_argument("--output", "-o", default=None,
                         help="Write to this file instead of stdout (only with --dump).")
    parser.add_argument("--timeout", type=float, default=DEFAULT_SCAN_SECONDS,
                         help=f"Seconds to scan for devices before dumping, only with --dump "
                              f"(default: {DEFAULT_SCAN_SECONDS}).")
    args = parser.parse_args()

    if args.dump:
        asyncio.run(dump(args.output, args.timeout))
        return

    bridge = CoreBridge()
    bridge.start()
    run(bridge)


if __name__ == "__main__":
    main()
