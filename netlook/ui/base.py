"""The shared View Model: toolkit-agnostic dataclasses describing what a device's row
should show, plus the one async function that builds them from live domain state.
Both frontends (ui/dpg.py, ui/textual.py) render from this instead of each
re-implementing category filtering, the silent/actionable/expandable-but-empty
branching, or the raw-properties dump - that logic lives here, once.

Deliberately not in core/: a "row" and "tabs" are UI-shape concepts core/ has no
business knowing about, even though this module itself imports nothing from any UI
toolkit - it only depends on core/ types.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.actions import Action, display_name
from ..core.models import Device, GROUPED_CATEGORIES, Resource, ResourceCategory, Service
from ..core.scanner import NetworkScanner


@dataclass
class ActionView:
    """A single clickable (or form-backed) action, ready to render."""
    label: str
    fields: tuple[str, ...]
    action: Action


@dataclass
class ServiceOverviewEntry:
    """One service's contribution to the compact row / Overview tab. Only ever
    included in DeviceRowView.overview if it has something to show - a permanently
    silent, non-expandable service (e.g. pdl-datastream) contributes nothing, not a
    placeholder entry, matching the "no plain-text labels in the compact view" rule.

    view_category_labels' label text is deliberately just the bare category name
    (e.g. "File Shares"), matching CategoryTabView.category.value exactly, so a
    button and the tab it opens are never named differently. A renderer should only
    show these in the collapsed row, not the expanded view's Overview tab: once
    real category tabs are visible right there, a duplicate "go to that tab" button
    inside Overview is redundant, not just visually but as an affordance - actions
    (below) are what stay identical between collapsed and Overview, not this."""
    kind: str
    actions: list[ActionView]  # empty if the service has nothing immediate to offer
    # [(category, "File Shares"), ...] - one per category, for an expandable service
    # whose immediate actions are always empty (e.g. smb): clicking one of these
    # should expand the row, not launch anything.
    view_category_labels: list[tuple[ResourceCategory, str]]


@dataclass
class CategoryEntry:
    """One service's contribution to a single category tab. Self-contained: a
    renderer never needs to re-derive "show the fallback label instead" logic -
    fallback_label is already None unless that's genuinely what should render."""
    kind: str
    actions: list[ActionView]
    status_text: str | None
    fallback_label: str | None  # display_name(kind), only set when actions and status_text are both empty


@dataclass
class CategoryTabView:
    category: ResourceCategory
    entries: list[CategoryEntry]


@dataclass
class PropertyEntry:
    kind: str
    port: int
    properties: list[tuple[str, str]]  # decoded (key, value) pairs; empty means none advertised


@dataclass
class PropertiesTabView:
    ip: str
    ipv6: str | None
    services: list[PropertyEntry]
    # (interface name, mac address) pairs - empty for every device except this
    # machine's own entry (see Device.physical_interfaces). A renderer shows the
    # "Physical Devices" section only when this is non-empty.
    physical_devices: list[tuple[str, str]]


def properties_section_ids(properties: PropertiesTabView) -> list[str]:
    """The ordered list of section identifiers a Properties tab currently renders
    as its own collapsible block: "physical_devices" (only if there's anything
    there) first, then each service with at least one non-blank-keyed property -
    matching exactly the skip condition a renderer applies when deciding whether
    to draw a section at all (see _add_properties_tab/_compose_properties_tab), so
    "expand all"/"collapse all" never operates on a section that was never shown.
    Shared here rather than each renderer re-deriving it independently."""
    ids = []
    if properties.physical_devices:
        ids.append("physical_devices")
    ids.extend(entry.kind for entry in properties.services if any(key.strip() for key, _ in entry.properties))
    return ids


@dataclass
class NamesTabView:
    """The Names tab's own content: hostname + aliases, each with provenance, plus
    the icon shown alongside them. hostname/hostname_sources/icon_path are also
    kept on DeviceRowView directly (mirroring how PropertiesTabView.ip duplicates
    DeviceRowView.ip) since the collapsed row and the tab's own label need them
    independent of whether this tab is ever opened; aliases has no use outside
    this tab, so it lives here only."""
    hostname: str
    hostname_sources: set[str]
    icon_path: str | None
    aliases: dict[str, set[str]]


@dataclass
class DeviceRowView:
    ip: str
    hostname: str
    hostname_sources: set[str]  # provenance for `hostname` itself - Device.aliases excludes it
    icon_path: str | None
    overview: list[ServiceOverviewEntry]
    category_tabs: list[CategoryTabView]  # only categories with a matching service on this device
    properties: PropertiesTabView
    names: NamesTabView


def _decode_txt_record(value: bytes | None) -> str:
    return value.decode(errors="replace") if value is not None else "(present, no value)"


def _build_entry(service: Service, category: ResourceCategory,
                  resources_by_kind: dict[str, list[Resource]]) -> CategoryEntry | None:
    """The default, one-entry-per-service case for a category tab. Returns None -
    no entry at all, not a fallback-label placeholder - for a service with nothing
    to show: this entry's own header is display_name(service.kind), the exact same
    string a fallback label would show here, so showing both would just print the
    same text twice (e.g. a "Workstation" header sitting over a "Workstation"
    fallback line). That's not "confirms it was detected" the way it reads for a
    grouped category (see _build_grouped_entry) - it's a service that's *always*
    silent (a permanently-informational kind like device-info, or a base-Service
    kind with no launch scheme or web admin page registered), whose properties are
    already comprehensively shown in the Properties tab. Nothing is lost, just not
    repeated here."""
    actions = [
        ActionView(r.action.label, r.action.fields, r.action)
        for r in resources_by_kind[service.kind]
        if r.category == category
    ]
    status_text = service.status_text
    if not actions and not status_text:
        return None
    return CategoryEntry(kind=service.kind, actions=actions, status_text=status_text, fallback_label=None)


def _build_grouped_entry(services: list[Service], category: ResourceCategory,
                          resources_by_kind: dict[str, list[Resource]], group_kind: str) -> CategoryEntry:
    """Combines every matching service's contribution into one CategoryEntry under
    one shared header (group_kind, e.g. "printer-group") instead of one per
    service - see GROUPED_CATEGORIES for why. status_texts are joined rather than
    picking just one, since more than one matching service could plausibly have
    something to say at once (today, only Cups ever actually does); fallback_label
    only applies if the whole group has nothing else to show, matching the
    single-service rule in _build_entry, just aggregated across the group."""
    actions = [
        ActionView(r.action.label, r.action.fields, r.action)
        for service in services
        for r in resources_by_kind[service.kind]
        if r.category == category
    ]
    status_texts = [service.status_text for service in services if service.status_text]
    status_text = ", ".join(status_texts) if status_texts else None
    fallback_label = None
    if not actions and not status_text:
        fallback_label = ", ".join(display_name(service.kind) for service in services)
    return CategoryEntry(kind=group_kind, actions=actions, status_text=status_text, fallback_label=fallback_label)


async def build_device_row_view(dev: Device, scanner: NetworkScanner, expanded: bool = False) -> DeviceRowView:
    """`expanded` gates category_tabs entirely, not just their rendering: building
    them calls get_resources(expanded=True, ...), which is exactly what triggers a
    not-yet-fetched service's lazy fetch (scanner.request_items(...)). Computing
    category_tabs unconditionally for every device on every refresh - regardless of
    whether any frontend has that row open - would silently reintroduce the eager,
    unprompted-fetch problem lazy loading exists to prevent (e.g. anonymous SMB auth
    attempts against every discovered device, not just ones a user actually opened).
    overview and properties are always safe to build: overview only ever calls
    get_resources(expanded=False, ...), which never fetches; properties only reads
    already-discovered service.properties, never triggering anything either."""
    overview: list[ServiceOverviewEntry] = []
    for service in dev.services.values():
        actions = [
            ActionView(r.action.label, r.action.fields, r.action)
            async for r in service.get_resources(expanded=False, scanner=scanner)
        ]
        view_category_labels = []
        if not actions and service.expandable:
            view_category_labels = [
                (category, category.value)
                for category in ResourceCategory
                if category in service.categories
            ]
        if actions or view_category_labels:
            overview.append(ServiceOverviewEntry(
                kind=service.kind, actions=actions, view_category_labels=view_category_labels,
            ))

    category_tabs: list[CategoryTabView] = []
    if expanded:
        # Each service's resources are computed once here, not once per category it
        # spans - a multi-category service (ssh) is only asked once; grouping by
        # resource.category happens below instead of asking the service to filter
        # itself against a category parameter repeatedly.
        resources_by_kind: dict[str, list[Resource]] = {}
        for service in dev.services.values():
            resources_by_kind[service.kind] = [
                r async for r in service.get_resources(expanded=True, scanner=scanner)
            ]

        for category in ResourceCategory:
            matching = [s for s in dev.services.values() if category in s.categories]
            if not matching:
                continue
            group_kind = GROUPED_CATEGORIES.get(category)
            if group_kind is not None:
                entries = [_build_grouped_entry(matching, category, resources_by_kind, group_kind)]
            else:
                entries = [
                    entry for service in matching
                    if (entry := _build_entry(service, category, resources_by_kind)) is not None
                ]
            # A non-grouped category where every matching service turned out to
            # have nothing to show (see _build_entry) would otherwise render as an
            # empty tab - skip it entirely rather than show a blank "System" or
            # "Other" tab for a device whose only match there is purely
            # informational (e.g. device-info, already reflected in this device's
            # own name, and in Properties).
            if not entries:
                continue
            category_tabs.append(CategoryTabView(category=category, entries=entries))

    property_entries = [
        PropertyEntry(
            kind=kind, port=service.port,
            # extra_properties (runtime diagnostic detail, e.g. Incus's real error
            # message) comes first - it's what the user most likely came here
            # looking for - followed by the service's raw advertised mDNS TXT
            # records.
            properties=service.extra_properties() + [
                (key.decode(errors="replace"), _decode_txt_record(value))
                for key, value in sorted(service.properties.items())
            ],
        )
        for kind, service in sorted(dev.services.items())
    ]

    return DeviceRowView(
        ip=dev.ip,
        hostname=dev.hostname,
        hostname_sources=set(dev.names.get(dev.hostname, set())),
        icon_path=dev.icon_path,
        overview=overview,
        category_tabs=category_tabs,
        properties=PropertiesTabView(
            ip=dev.ip, ipv6=dev.ipv6, services=property_entries,
            physical_devices=list(dev.physical_interfaces),
        ),
        names=NamesTabView(
            hostname=dev.hostname, hostname_sources=set(dev.names.get(dev.hostname, set())),
            icon_path=dev.icon_path, aliases=dict(dev.aliases),
        ),
    )


def _action_to_dict(action_view: ActionView) -> dict:
    """label/fields/uri only - never dumped via dataclasses.asdict() on the whole
    ActionView, since some Action subclasses embed a full Service reference
    (CredentialAction.service) whose own properties dict has bytes keys that don't
    serialize to JSON at all. This is a deliberate, explicit allowlist of what's
    actually worth exporting, not a blind recursive dump."""
    return {"label": action_view.label, "fields": list(action_view.fields),
            "uri": getattr(action_view.action, "uri", None)}


def device_row_view_to_dict(view: DeviceRowView) -> dict:
    """A JSON-safe snapshot of everything a device's row currently shows - the
    Save feature's per-device unit. Built by hand, field by field (see
    _action_to_dict for why), rather than a blind dataclasses.asdict()."""
    return {
        "ip": view.ip,
        "hostname": view.hostname,
        "names": {
            "hostname": view.names.hostname,
            "hostname_sources": sorted(view.names.hostname_sources),
            "icon_path": view.names.icon_path,
            "aliases": {name: sorted(sources) for name, sources in view.names.aliases.items()},
        },
        "overview": [
            {
                "kind": entry.kind,
                "actions": [_action_to_dict(a) for a in entry.actions],
                "view_category_labels": [[category.value, label] for category, label in entry.view_category_labels],
            }
            for entry in view.overview
        ],
        "category_tabs": [
            {
                "category": tab.category.value,
                "entries": [
                    {
                        "kind": entry.kind,
                        "actions": [_action_to_dict(a) for a in entry.actions],
                        "status_text": entry.status_text,
                        "fallback_label": entry.fallback_label,
                    }
                    for entry in tab.entries
                ],
            }
            for tab in view.category_tabs
        ],
        "properties": {
            "ip": view.properties.ip,
            "ipv6": view.properties.ipv6,
            "services": [
                {"kind": s.kind, "port": s.port, "properties": [list(p) for p in s.properties]}
                for s in view.properties.services
            ],
            "physical_devices": [list(p) for p in view.properties.physical_devices],
        },
    }


DEFAULT_SAVE_PATH = "netlook-devices.json"


def build_devices_payload(views: list[DeviceRowView]) -> dict:
    """The saved_at/devices JSON shape shared by every consumer of device data -
    both frontends' Save button (via save_devices_to_json below) and the CLI's
    --dump (which prints this same shape to stdout when no --output is given,
    rather than duplicating the shape inline)."""
    return {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "devices": [device_row_view_to_dict(v) for v in views],
    }


def save_devices_to_json(views: list[DeviceRowView], path: str = DEFAULT_SAVE_PATH) -> None:
    """Writes every given device's current row data to a JSON file - shared by
    both frontends' Save button/action, so the file shape and the "what counts as
    a device's data" decision (see device_row_view_to_dict) live in exactly one
    place. Takes already-built views rather than building them itself: each
    frontend already has (or can cheaply build) views reflecting whatever's
    currently expanded, and re-deriving that here would either duplicate that
    logic or force every device to "expand" just to be saved - triggering the
    same eager, unprompted fetches lazy loading exists to prevent."""
    with open(path, "w") as f:
        json.dump(build_devices_payload(views), f, indent=2)


# Logical tab identifiers shared by both frontends' active_tab tracking below - a
# category tab uses its ResourceCategory.name (e.g. "FILE_SHARES") instead of a
# third constant, since that's already a stable, unique-per-category string.
NAMES_TAB_ID = "names"
PROPERTIES_TAB_ID = "properties"


@dataclass
class ViewModelState:
    """Per-frontend-instance UI state that isn't part of the domain model itself -
    which device rows are expanded, what's currently typed into any open forms, and
    which tab should be active once a row is expanded. Each frontend (DPG, Textual)
    owns its own instance, since a user could have different rows expanded (and
    different tabs active) in each."""
    expanded_devices: set[str] = field(default_factory=set)
    # (ip, kind, category) -> {field name: value}, keyed loosely by convention rather
    # than a rigid type since it's populated/read entirely by each renderer's own
    # form widgets - this module never touches the values, just holds them.
    form_input_cache: dict = field(default_factory=dict)
    # ip -> the tab id (NAMES_TAB_ID, PROPERTIES_TAB_ID, or a ResourceCategory's
    # .name) that should be active once that device's row is expanded - absent
    # means "no explicit request, default to Names" (see get_active_tab). Tracked
    # persistently, not just set once on expand: both frontends fully rebuild a
    # device's row on every refresh (there's no widget to just leave alone), so
    # without this an unrelated refresh would silently reset back to the first tab
    # even after the user had manually switched to another one.
    active_tab: dict[str, str] = field(default_factory=dict)
    # (ip, section_id) -> whether that Properties-tab section (see
    # properties_section_ids) is currently expanded. Absent means collapsed - the
    # default for a section neither frontend has ever built a widget for yet.
    properties_expanded: dict[tuple[str, str], bool] = field(default_factory=dict)

    def is_expanded(self, ip: str) -> bool:
        return ip in self.expanded_devices

    def toggle_expanded(self, ip: str) -> None:
        if ip in self.expanded_devices:
            self.expanded_devices.discard(ip)
        else:
            self.expanded_devices.add(ip)

    def expand(self, ip: str, category: ResourceCategory | None = None) -> None:
        """Unlike toggle_expanded, never collapses an already-open row - for a
        [View <Category>] button, which should only ever open, never accidentally
        close a row the user is already looking at. `category`, when given, also
        requests that tab be the one active once expanded, instead of always
        landing back on Names."""
        self.expanded_devices.add(ip)
        if category is not None:
            self.active_tab[ip] = category.name

    def get_active_tab(self, ip: str) -> str:
        return self.active_tab.get(ip, NAMES_TAB_ID)

    def set_active_tab(self, ip: str, tab_id: str) -> None:
        self.active_tab[ip] = tab_id

    def is_properties_section_expanded(self, ip: str, section_id: str) -> bool:
        return self.properties_expanded.get((ip, section_id), False)

    def set_properties_section_expanded(self, ip: str, section_id: str, expanded: bool) -> None:
        self.properties_expanded[(ip, section_id)] = expanded

    def all_properties_expanded(self, ip: str, section_ids: list[str]) -> bool:
        """Whether every given section is currently expanded - used to decide the
        Expand All/Collapse All button's own label and what clicking it should do
        next. False (not "Collapse All") for a device with no sections at all,
        since there's nothing to collapse."""
        return bool(section_ids) and all(self.is_properties_section_expanded(ip, s) for s in section_ids)
