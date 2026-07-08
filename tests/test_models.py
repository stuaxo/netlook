"""Unit tests for netlook.core.models."""
import pytest

from netlook.core.models import (
    Device,
    ResourceCategory,
    Service,
    kind_from_type,
    make_service,
    register,
)


@pytest.mark.parametrize("type_or_name, expected_kind", [
    ("_ssh._tcp.local.", "ssh"),
    ("_smb._tcp.local.", "smb"),
    ("_rfb._tcp.local.", "vnc"),
    ("cups", "cups"),
])
def test_kind_from_type_normalizes_mdns_and_probe_strings(type_or_name, expected_kind):
    """Verify that kind_from_type extracts the canonical service kind from either an
    mDNS type string or an already-clean probe kind, by stripping the leading
    underscore/suffix and applying KIND_ALIASES for kinds like VNC's "_rfb._tcp"."""
    kind = kind_from_type(type_or_name)

    assert kind == expected_kind


def test_register_maps_every_given_kind_to_the_decorated_class(service_registry):
    """Verify that the @register decorator maps every given kind to the decorated
    class, by decorating a throwaway Service subclass and checking SERVICE_REGISTRY.
    Uses the service_registry fixture so the throwaway entries don't leak into the
    rest of the suite."""
    @register("widget", "gadget")
    class Widget(Service):
        pass

    assert service_registry["widget"] is Widget
    assert service_registry["gadget"] is Widget


def test_make_service_uses_the_registered_subclass_when_one_is_known():
    """Verify that make_service returns an instance of the registered subclass for a
    known kind, by checking the class of a "smb" service registered by services.py."""
    from netlook.core import services  # noqa: F401 - import triggers @register

    service = make_service("smb", "10.0.0.5", 445)

    assert type(service).__name__ == "Samba"


def test_make_service_falls_back_to_the_base_service_for_an_unregistered_kind(empty_service_registry):
    """Verify that make_service returns a plain Service when nothing has registered
    for a given kind, by checking this holds even for "smb" once the registry is
    empty - not just for a made-up kind that happens not to collide with anything
    services.py has really registered."""
    service = make_service("smb", "10.0.0.5", 445)

    assert type(service) is Service


def test_service_enrich_device_offers_the_discovered_name_as_an_alias():
    """Verify that the base Service.enrich_device offers its mDNS instance name as an
    alias sourced under its own kind, by checking Device.names after enrichment."""
    device = Device("seed", "10.0.0.5", names={"seed": {"seed-source"}})
    service = Service(kind="ssh", ip="10.0.0.5", port=22, discovered_name="myhost")

    service.enrich_device(device)

    assert device.names["myhost"] == {"ssh"}


def test_service_enrich_device_is_a_noop_without_a_discovered_name():
    """Verify that the base Service.enrich_device does nothing for a probe-only
    service with no mDNS instance name, by checking Device.names is unchanged."""
    device = Device("seed", "10.0.0.5", names={"seed": {"seed-source"}})
    service = Service(kind="ssh", ip="10.0.0.5", port=22, discovered_name=None)

    service.enrich_device(device)

    assert device.names == {"seed": {"seed-source"}}


@pytest.mark.parametrize("kind, expected_labels", [
    ("rdp", ["Remote Desktop (RDP)"]),
    ("vnc", ["Screen Sharing (VNC)"]),
    ("home-assistant", ["Home Assistant admin"]),
    ("hue", []),  # not in LAUNCH_KINDS or WEB_ADMIN - no default action
])
async def test_base_service_get_resources_covers_launch_and_web_admin_kinds(kind, expected_labels):
    """Verify that the base Service.get_resources yields a launch resource for
    LAUNCH_KINDS, a web-admin resource for WEB_ADMIN kinds, and nothing for any
    other kind, by comparing yielded action labels across a few representative
    kinds."""
    service = Service(kind=kind, ip="10.0.0.5", port=1234)

    labels = [r.action.label async for r in service.get_resources(expanded=False, scanner=None)]

    assert labels == expected_labels


async def test_base_service_get_resources_yields_the_same_resource_regardless_of_expanded():
    """Verify that the base Service.get_resources ignores expanded and yields the
    same resource either way, by checking a LAUNCH_KINDS service's resource is
    identical collapsed and expanded. The base class has no deeper, per-resource
    content to reveal once expanded (unlike smb/incus/cups, which register their
    own subclass specifically because they do), so its category tab must keep
    showing the same resource Overview does - a dead, actionless tab would be a
    regression, not a simplification, for a service that plainly has something to
    click."""
    service = Service(kind="rdp", ip="10.0.0.5", port=3389)

    collapsed = [r async for r in service.get_resources(expanded=False, scanner=None)]
    expanded = [r async for r in service.get_resources(expanded=True, scanner=None)]

    assert len(expanded) == 1
    assert expanded == collapsed


def test_device_add_service_creates_a_service_and_enriches_only_once():
    """Verify that Device.add_service creates exactly one Service per kind and only
    enriches on first creation, by re-adding the same kind with different details
    and checking the second call is ignored entirely."""
    device = Device("seed", "10.0.0.5")

    device.add_service("_ssh._tcp.local.", 22, {}, "first-name")
    device.add_service("_ssh._tcp.local.", 2222, {}, "second-name")

    assert list(device.services) == ["ssh"]
    assert device.services["ssh"].port == 22
    assert "first-name" in device.names
    assert "second-name" not in device.names


@pytest.mark.parametrize("name", ["", "   "])
def test_promote_name_ignores_blank_names(name):
    """Verify that Device.promote_name is a no-op for a blank or whitespace-only
    name, by checking the hostname and provenance dict are left untouched."""
    device = Device("original", "10.0.0.5", names={"original": {"seed"}})

    device.promote_name("some-source", name)

    assert device.hostname == "original"
    assert device.names == {"original": {"seed"}}


def test_promote_name_demotes_the_current_hostname_to_an_alias():
    """Verify that Device.promote_name makes the new name primary while keeping the
    old hostname discoverable, by promoting a second name and checking the old one
    survives in `names` and reappears via `aliases`."""
    device = Device("MyNAS", "10.0.0.5", names={"MyNAS": {"smb"}})

    device.promote_name("device-info", "Stuart's NAS")

    assert device.hostname == "Stuart's NAS"
    assert device.names == {"MyNAS": {"smb"}, "Stuart's NAS": {"device-info"}}
    assert device.aliases == {"MyNAS": {"smb"}}


def test_add_alias_merges_sources_when_two_engines_agree_on_a_name():
    """Verify that Device.add_alias merges sources into a single entry when two
    different sources report the identical name, by adding the same name twice with
    different sources and checking `names` has one entry with both - not two."""
    device = Device("printer.local", "10.0.0.9", names={"printer.local": {"ipp"}})

    device.add_alias("http", "printer.local")

    assert device.names == {"printer.local": {"ipp", "http"}}


def test_aliases_excludes_only_the_current_primary_name():
    """Verify that Device.aliases returns every known name except whichever one is
    currently the hostname, by checking a name that used to be primary reappears in
    aliases once a different name is promoted over it."""
    device = Device("MyNAS", "10.0.0.5", names={"MyNAS": {"smb"}, "MyNAS-ssh": {"ssh"}})

    device.promote_name("device-info", "Stuart's NAS")

    assert device.aliases == {"MyNAS": {"smb"}, "MyNAS-ssh": {"ssh"}}


def test_service_category_definition_order_is_the_ui_tab_order():
    """Verify that ResourceCategory's definition order is Printers, Screen Share,
    Terminal, File Shares, Virtual Machines, System, Other, since the UI iterates
    the enum directly to decide tab order, by checking the enum's iteration order
    matches exactly."""
    assert list(ResourceCategory) == [
        ResourceCategory.PRINTERS,
        ResourceCategory.SCREEN_SHARE,
        ResourceCategory.TERMINAL,
        ResourceCategory.FILE_SHARES,
        ResourceCategory.VIRTUAL_MACHINES,
        ResourceCategory.SYSTEM,
        ResourceCategory.OTHER,
    ]


@pytest.mark.parametrize("kind, expected_categories", [
    ("ssh", {ResourceCategory.TERMINAL, ResourceCategory.FILE_SHARES}),
    ("smb", {ResourceCategory.FILE_SHARES}),
    ("cups", {ResourceCategory.PRINTERS}),
    ("incus", {ResourceCategory.VIRTUAL_MACHINES}),
    ("some-unregistered-kind", {ResourceCategory.OTHER}),
])
def test_service_categories_property_reflects_service_categories_dict(kind, expected_categories):
    """Verify that Service.categories returns SERVICE_CATEGORIES's entry for a known
    kind, and falls back to {OTHER} for anything not listed, by checking a
    multi-category kind (ssh offers two distinct resources - a terminal launch and
    an sftp browser - from one service), single-category kinds, and an unknown kind.
    smb is deliberately single-category despite being able to host printer shares
    too - see SERVICE_CATEGORIES's comment for why those render inside File Shares
    instead of getting their own tab."""
    service = Service(kind=kind, ip="10.0.0.5", port=1234)

    assert service.categories == expected_categories
