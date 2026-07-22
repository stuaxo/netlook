"""The shared View Model: toolkit-agnostic dataclasses describing what a
device's row should show, plus the one async function that builds them from
live domain state.

Both frontends (ui/dpg.py, ui/textual.py) render from this instead of each
re-implementing category filtering, silent/actionable/expandable-but-empty
branching, or the raw-properties dump.

Deliberately not in core/: "row" and "tabs" are UI-shape concepts core/ has
no business knowing about, even though this module imports nothing from any
UI toolkit itself - only core/ types.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.actions import Action, display_name
from ..core.discovery import FINDER_SOURCES
from ..core.models import Device, Fetchable, FetchState, GROUPED_CATEGORIES, Resource, ResourceCategory, Service
from ..core.scanner import NetworkScanner


@dataclass
class ActionView:
    """A single clickable (or form-backed) action, ready to render."""
    label: str
    fields: tuple[str, ...]
    action: Action


@dataclass
class ServiceOverviewEntry:
    """One service's contribution to the compact row / Overview tab.

    Only included in DeviceRowView.overview if it has something to show - a
    permanently silent, non-expandable service (e.g. pdl-datastream)
    contributes nothing, not a placeholder entry.

    view_category_labels' label text is just the bare category name (e.g.
    "File Shares"), matching CategoryTabView.category.value, so a button and
    the tab it opens are never named differently. A renderer should only
    show these in the collapsed row, not Overview: once real category tabs
    are visible, a duplicate "go to that tab" button there is redundant.
    `actions` is what stays identical between collapsed and Overview."""
    kind: str
    actions: list[ActionView]  # empty if the service has nothing immediate to offer
    # [(category, "File Shares"), ...] - one per category, for an expandable service
    # whose immediate actions are always empty (e.g. smb): clicking one of these
    # should expand the row, not launch anything.
    view_category_labels: list[tuple[ResourceCategory, str]]


@dataclass
class LoginPromptView:
    """Rendered instead of a CategoryEntry's actions/status_text when its
    service needs credentials before fetch() can proceed (see _build_entry).

    Submitting it calls scanner.request_items(service, **kwargs) directly
    via submit_login below, not action.run() - this is fetch-
    parameterization, not a launch action, so there's no Action/Resource
    behind it."""
    fields: tuple[str, ...]
    service: Service  # live reference, used only to submit - never serialized (see device_row_view_to_dict)
    failed: bool  # from service.tried_auth - Samba-specific, not part of the Fetchable contract itself


@dataclass
class CategoryEntry:
    """One service's contribution to a single category tab.

    Self-contained: a renderer never re-derives "show the fallback label
    instead" - fallback_label is already None unless that's what should
    render. login is mutually exclusive with actions/status_text/
    fallback_label - set only when this service needs credentials first."""
    kind: str
    actions: list[ActionView]
    status_text: str | None
    fallback_label: str | None  # display_name(kind), only set when actions and status_text are both empty
    login: LoginPromptView | None = None


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
class FinderEntry:
    """One discovery engine's Found/Not Found verdict for a device, per
    FINDER_SOURCES. The Properties tab's "Finders" section renders this
    list, so a user can see which engine(s) actually reported a device."""
    label: str
    found: bool


@dataclass
class PropertiesTabView:
    ip: str
    ipv6: str | None
    services: list[PropertyEntry]
    # (interface name, mac address) pairs - empty for every device except this
    # machine's own entry (see Device.physical_interfaces). A renderer shows the
    # "Physical Devices" section only when this is non-empty.
    physical_devices: list[tuple[str, str]]
    # One entry per discovery engine (FINDER_SOURCES order), always present -
    # unlike physical_devices/services below, this section never disappears, since
    # "not found by this engine" is exactly as informative as "found by it".
    finders: list[FinderEntry]
    # Reverse-DNS (PTR) name for `ip`, or None if none was found (or the lookup
    # hasn't been triggered yet - see build_device_row_view). Always present,
    # like finders: "no PTR record" is exactly as informative as one.
    dns_hostname: str | None


def properties_section_ids(properties: PropertiesTabView) -> list[str]:
    """The ordered list of section identifiers a Properties tab renders as a
    collapsible block: "finders" and "dns" (always), then "physical_devices" (if
    non-empty), then each service with at least one non-blank-keyed
    property - matching the skip condition a renderer applies when deciding
    whether to draw a section (see _add_properties_tab/
    _compose_properties_tab), so "expand all"/"collapse all" never touches a
    section that was never shown."""
    ids = ["finders", "dns"]
    if properties.physical_devices:
        ids.append("physical_devices")
    ids.extend(entry.kind for entry in properties.services if any(key.strip() for key, _ in entry.properties))
    return ids


@dataclass
class NamesTabView:
    """The Names tab's content: hostname + aliases, each with provenance,
    plus the icon shown alongside them.

    hostname/hostname_sources/icon_path are also kept on DeviceRowView
    directly (mirroring PropertiesTabView.ip duplicating DeviceRowView.ip),
    since the collapsed row needs them whether or not this tab is opened.
    aliases has no use outside this tab, so it lives here only."""
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
    """The default, one-entry-per-service case for a category tab.

    Returns None - no entry, not a fallback-label placeholder - for a
    service with nothing to show: its header would already be
    display_name(service.kind), identical to what a fallback label would
    print, so showing both would just repeat the same text (e.g. a
    "Workstation" header over a "Workstation" fallback line). This covers a
    service that's always silent (a permanently-informational kind like
    device-info, or a base-Service kind with no launch scheme or web admin
    page), whose properties already show in the Properties tab.

    A Fetchable service currently AUTH_REQUIRED (only Samba, today)
    short-circuits into a LoginPromptView instead of its actions/status_text
    - reading fetch_state here is for rendering, not a decision to act (see
    NetworkScanner.ensure_fetched for that decision, made before this is
    ever called)."""
    if isinstance(service, Fetchable) and service.fetch_state == FetchState.AUTH_REQUIRED:
        login = LoginPromptView(fields=service.fetch_fields(), service=service,
                                 failed=getattr(service, "tried_auth", False))
        return CategoryEntry(kind=service.kind, actions=[], status_text=None, fallback_label=None, login=login)
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
    """Combines every matching service's contribution into one CategoryEntry
    under one shared header (group_kind, e.g. "printer-group") instead of
    one per service - see GROUPED_CATEGORIES for why.

    status_texts are joined rather than picking one, since more than one
    matching service could have something to say (today, only Cups does).
    fallback_label applies only if the whole group has nothing else to show,
    the same rule as _build_entry, aggregated across the group.

    Doesn't check for a login prompt the way _build_entry does - no
    Fetchable service is a member of a grouped category today (only
    Printers is grouped, and smb isn't in it). A future Fetchable service
    joining a grouped category would need the same AUTH_REQUIRED handling
    added here."""
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
    """`expanded` gates category_tabs entirely, not just their rendering:
    building them calls scanner.ensure_fetched(service) for every service on
    this device, which triggers a not-yet-fetched Fetchable service's lazy
    fetch. Computing category_tabs unconditionally on every refresh - whether
    or not any frontend has that row open - would reintroduce the eager,
    unprompted-fetch problem lazy loading exists to prevent (e.g. anonymous
    SMB auth attempts against every discovered device).

    overview and properties are always safe to build: overview only reads
    service.resources() filtered to .immediate, which never triggers a fetch
    (resources() is pure - see models.Service.resources); properties only
    reads already-discovered service.properties."""
    overview: list[ServiceOverviewEntry] = []
    for service in dev.services.values():
        actions = [
            ActionView(r.action.label, r.action.fields, r.action)
            for r in service.resources() if r.immediate
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
        # Triggering the reverse-DNS lookup only once a row actually expands
        # mirrors ensure_fetched below - a live PTR lookup for every device on
        # every refresh, whether anyone's looking or not, is the same
        # unprompted-network-call problem lazy loading exists to prevent.
        await scanner.ensure_dns_resolved(dev)

        # Each service's resources are computed once here, not once per
        # category it spans - a multi-category service (ssh) is only asked
        # once; grouping by resource.category happens below instead.
        # ensure_fetched is called for every service unconditionally, not
        # just ones matching a category below - same as the old
        # get_resources(expanded=True, ...) this replaces.
        resources_by_kind: dict[str, list[Resource]] = {}
        for service in dev.services.values():
            await scanner.ensure_fetched(service)
            resources_by_kind[service.kind] = list(service.resources())

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
            # A non-grouped category where every matching service has
            # nothing to show (see _build_entry) would otherwise render as
            # an empty tab - skip it rather than show a blank "System" or
            # "Other" tab for a device whose only match there is purely
            # informational (e.g. device-info).
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
            finders=[FinderEntry(label, source in dev.found_by) for label, source in FINDER_SOURCES],
            dns_hostname=dev.dns_hostname,
        ),
        names=NamesTabView(
            hostname=dev.hostname, hostname_sources=set(dev.names.get(dev.hostname, set())),
            icon_path=dev.icon_path, aliases=dict(dev.aliases),
        ),
    )


async def submit_login(scanner: NetworkScanner, login: LoginPromptView, **values) -> None:
    """Resubmits the owning service's fetch with credentials - the
    login-prompt equivalent of ActionView's action.run(scanner, **kwargs),
    but calling scanner.request_items directly since a login prompt isn't an
    Action.

    Only "user" is trimmed (matching smbclient's tolerance for whitespace
    around a username but not a password) - normalisation lives here once,
    instead of duplicated in both frontends' submit handlers."""
    kwargs = {name: (value.strip() if name == "user" else value) for name, value in values.items()}
    await scanner.request_items(login.service, **kwargs)


def _action_to_dict(action_view: ActionView) -> dict:
    """label/fields/uri only - an explicit allowlist of what's worth
    exporting, not a blind dataclasses.asdict() dump of the whole ActionView.

    LoginPromptView needs the same care: it carries a live Service reference
    whose properties dict has bytes keys that don't serialize to JSON, which
    is why its own dict shape only exports `fields`, never the service."""
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
                        # Present (nullable) for every entry, matching status_text/
                        # fallback_label's convention - only set when this service
                        # needs credentials before it can offer anything else. Just
                        # the field names: `failed` and the live service reference
                        # aren't serializable data, they're transient sign-in UI
                        # state and a live object respectively (see _action_to_dict).
                        "login_fields": list(entry.login.fields) if entry.login else None,
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
            "finders": [{"label": f.label, "found": f.found} for f in view.properties.finders],
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
    """Writes every given device's current row data to a JSON file - shared
    by both frontends' Save button, so the file shape (see
    device_row_view_to_dict) lives in one place.

    Takes already-built views rather than building them itself: each
    frontend already has views reflecting whatever's expanded, and
    rebuilding here would either duplicate that logic or force every device
    to "expand" just to be saved - triggering the eager fetches lazy loading
    exists to prevent."""
    with open(path, "w") as f:
        json.dump(build_devices_payload(views), f, indent=2)


# Logical tab identifiers shared by both frontends' active_tab tracking below - a
# category tab uses its ResourceCategory.name (e.g. "FILE_SHARES") instead of a
# third constant, since that's already a stable, unique-per-category string.
NAMES_TAB_ID = "names"
PROPERTIES_TAB_ID = "properties"


@dataclass
class ViewModelState:
    """Per-frontend-instance UI state that isn't part of the domain model -
    which rows are expanded, what's typed into open forms, and which tab is
    active once a row expands. Each frontend (DPG, Textual) owns its own
    instance, since a user could have different rows/tabs open in each."""
    expanded_devices: set[str] = field(default_factory=set)
    # (ip, kind, category) -> {field name: value}, keyed loosely by
    # convention since it's populated/read entirely by each renderer's form
    # widgets - this module never touches the values, just holds them.
    form_input_cache: dict = field(default_factory=dict)
    # ip -> the tab id (NAMES_TAB_ID, PROPERTIES_TAB_ID, or a
    # ResourceCategory's .name) active once that device's row expands.
    # Absent means "default to Names" (see get_active_tab). Tracked
    # persistently, not just set on expand: both frontends fully rebuild a
    # row on every refresh, so without this a refresh would reset back to
    # the first tab even after the user switched away.
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
        """Unlike toggle_expanded, never collapses an already-open row - for
        a [View <Category>] button, which should only open, never
        accidentally close a row the user is already looking at. `category`,
        when given, also sets that tab active once expanded, instead of
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
