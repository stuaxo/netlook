"""Unit tests for netlook.core.models."""
import pytest

from netlook.core.models import (
    Device,
    ResourceCategory,
    Service,
    kind_from_type,
    make_service,
    register,
    remote_session_action,
    web_admin_action,
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


def test_remote_session_action_builds_a_scheme_uri_and_readable_label():
    """Verify that remote_session_action builds a scheme://ip:port uri, a
    human-readable label, and prefers remmina, by checking all three against an
    ssh-kind service."""
    service = Service(kind="ssh", ip="10.0.0.5", port=22)

    action = remote_session_action(service)

    assert action.uri == "ssh://10.0.0.5:22"
    assert action.label == "Secure Shell (SSH)"
    assert action.opener == "remmina"


@pytest.mark.parametrize("port_override, expected_port", [
    (None, 8443),    # falls back to the service's own detected port
    (47990, 47990),  # explicit override, e.g. Sunshine's config UI
])
def test_web_admin_action_honors_the_port_override(port_override, expected_port):
    """Verify that web_admin_action uses the service's own port unless an explicit
    override is given, and defaults to the xdg-open opener, by comparing the built
    uri's port for both cases."""
    service = Service(kind="incus", ip="10.0.0.5", port=8443)

    action = web_admin_action(service, path="/ui/", scheme="https", port=port_override)

    assert action.uri == f"https://10.0.0.5:{expected_port}/ui/"
    assert action.opener == "xdg-open"


@pytest.mark.parametrize("kind, expected_labels", [
    ("rdp", ["Remote Desktop (RDP)"]),
    ("vnc", ["Screen Sharing (VNC)"]),
    ("home-assistant", ["Home Assistant admin"]),
    ("hue", []),  # not in LAUNCH_KINDS or WEB_ADMIN - no default action
])
def test_base_service_resources_covers_launch_and_web_admin_kinds(kind, expected_labels):
    """Verify that the base Service.resources yields a launch resource for
    LAUNCH_KINDS, a web-admin resource for WEB_ADMIN kinds, and nothing for any
    other kind, by comparing yielded action labels across a few representative
    kinds."""
    service = Service(kind=kind, ip="10.0.0.5", port=1234)

    labels = [r.action.label for r in service.resources()]

    assert labels == expected_labels


def test_base_service_resources_marks_its_one_resource_as_immediate():
    """Verify that the base Service.resources tags its resource as immediate
    (visible in the collapsed row), by checking a LAUNCH_KINDS service. The base
    class has no deeper, per-resource content to reveal once expanded (unlike
    smb/incus/cups, which register their own subclass specifically because they
    do), so its category tab must keep showing the same resource Overview does -
    a dead, actionless tab would be a regression, not a simplification, for a
    service that plainly has something to click."""
    service = Service(kind="rdp", ip="10.0.0.5", port=3389)

    resources = list(service.resources())

    assert len(resources) == 1
    assert resources[0].immediate is True


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


def test_smb_host_prefers_an_mdns_name_over_a_wsd_name_and_addresses():
    """Verify that Device.smb_host picks an mDNS-sourced name (suffixed with
    ".local" - see the ".local" test below) ahead of a WSD (wsdd) name and both
    address fallbacks, regardless of insertion order."""
    device = Device("MyNAS", "10.0.0.5", ipv6="fe80::1",
                     names={"MYNAS-wsd": {"WSD"}, "MyNAS": {"smb"}})

    assert device.smb_host() == "MyNAS.local"


def test_smb_host_appends_dot_local_to_a_bare_mdns_name():
    """Verify that Device.smb_host suffixes a bare (undotted) mDNS-sourced name
    with ".local" - glibc's nss-mdns (mdns4_minimal) only intercepts a lookup
    that's actually suffixed with ".local"; a bare NetBIOS-style lookup falls
    through to WINS/broadcast resolution instead, which failed to resolve a real
    device's mDNS name ("werner") until ".local" was added by hand."""
    device = Device("werner", "10.0.0.5", names={"werner": {"smb"}})

    assert device.smb_host() == "werner.local"


def test_smb_host_leaves_an_already_dotted_mdns_name_alone():
    """Verify that Device.smb_host doesn't double-suffix an mDNS name that's
    already dotted (e.g. already ends in .local, or is some other FQDN)."""
    device = Device("nas.local", "10.0.0.5", names={"nas.local": {"smb"}})

    assert device.smb_host() == "nas.local"


def test_smb_host_falls_back_to_a_wsd_name_without_an_mdns_name():
    """Verify that Device.smb_host uses a WSD-sourced name when no mDNS name was
    ever reported."""
    device = Device("MyNAS", "10.0.0.5", ipv6="fe80::1", names={"MyNAS": {"WSD"}})

    assert device.smb_host() == "MyNAS"


def test_smb_host_skips_ssh_known_hosts_and_etc_hosts_names():
    """Verify that Device.smb_host doesn't treat a name sourced only from
    ssh-known-hosts/etc-hosts as an mDNS name - those aren't reliably the device's
    real network-resolvable name the way an mDNS or WSD name is - falling through to
    the address fallbacks instead."""
    device = Device("nas", "10.0.0.5", ipv6="fe80::1",
                     names={"nas": {"ssh-known-hosts", "etc-hosts"}})

    assert device.smb_host() == "fe80::1"


def test_smb_host_prefers_ipv6_over_ipv4_without_any_name():
    """Verify that Device.smb_host falls back to ipv6 before ipv4 when no naming
    source has reported anything at all."""
    device = Device("10.0.0.5", "10.0.0.5", ipv6="fe80::1")

    assert device.smb_host() == "fe80::1"


def test_smb_host_falls_back_to_ipv4_as_a_last_resort():
    """Verify that Device.smb_host falls back to the plain ipv4 address when there's
    no name and no ipv6 address either."""
    device = Device("10.0.0.5", "10.0.0.5")

    assert device.smb_host() == "10.0.0.5"


@pytest.mark.parametrize("name", ["Stuart's NAS", "Stuart's PC (office)", "living room, tv", "nas 01", "café"])
def test_smb_host_skips_an_mdns_name_that_isnt_a_valid_hostname(name):
    """Verify that Device.smb_host never returns an mDNS-sourced name containing a
    space, apostrophe, or other character invalid in a hostname - a human-friendly
    display label there (e.g. "Stuart's NAS") is exactly what used to get handed
    straight to GVfs as an smb:// uri authority, which rejects it outright
    ("invalid argument") since it isn't valid uri/hostname syntax at all, not
    something percent-encoding could fix - falling through to the address
    fallbacks instead."""
    device = Device(name, "10.0.0.5", names={name: {"smb"}})

    assert device.smb_host() == "10.0.0.5"


def test_smb_host_falls_through_a_bad_mdns_name_to_a_valid_wsd_name():
    """Verify that Device.smb_host tries the WSD tier when the only mDNS name isn't
    hostname-shaped, rather than giving up straight to an address - a bad name in
    one tier shouldn't skip past a good name in the next."""
    device = Device("Stuart's NAS", "10.0.0.5", names={"Stuart's NAS": {"smb"}, "nas01": {"WSD"}})

    assert device.smb_host() == "nas01"


@pytest.mark.parametrize("name", ["Stuart's NAS", "office printer share", "nas,01"])
def test_smb_host_skips_a_wsd_name_that_isnt_a_valid_hostname(name):
    """Verify that Device.smb_host applies the same hostname-shape check to a
    WSD-sourced name as it does to an mDNS one, falling back to an address rather
    than an unusable display name."""
    device = Device(name, "10.0.0.5", names={name: {"WSD"}})

    assert device.smb_host() == "10.0.0.5"


def test_ssh_host_prefers_a_known_hosts_name_over_etc_hosts_mdns_and_addresses():
    """Verify that Device.ssh_host picks a name sourced from ~/.ssh/known_hosts
    ahead of everything else - specifically so connecting here matches whatever
    name/form ssh itself already trusts for this host, avoiding a host-key
    mismatch prompt for what's really the same server under a different name."""
    device = Device("werner", "10.0.0.5", ipv6="fe80::1", names={
        "werner": {"ssh-known-hosts"}, "werner-hosts": {"etc-hosts"}, "werner.local": {"ssh"},
    })

    assert device.ssh_host() == "werner"


def test_ssh_host_falls_back_to_an_etc_hosts_name_without_a_known_hosts_name():
    """Verify that Device.ssh_host uses an /etc/hosts-sourced name ahead of an mDNS
    name and the address fallbacks when no known_hosts name was reported."""
    device = Device("werner", "10.0.0.5", ipv6="fe80::1",
                     names={"werner-hosts": {"etc-hosts"}, "werner": {"ssh"}})

    assert device.ssh_host() == "werner-hosts"


def test_ssh_host_falls_back_to_an_mdns_name_suffixed_with_dot_local():
    """Verify that Device.ssh_host falls back to an mDNS-sourced name, suffixed
    with ".local" the same way smb_host does (see _first_name), when neither
    known_hosts nor /etc/hosts named this device."""
    device = Device("werner", "10.0.0.5", ipv6="fe80::1", names={"werner": {"ssh"}})

    assert device.ssh_host() == "werner.local"


def test_ssh_host_falls_back_to_ipv6_then_ipv4_without_any_name():
    """Verify that Device.ssh_host falls back to ipv6 before ipv4 when no naming
    source has reported anything at all - same address-fallback order as
    smb_host."""
    assert Device("10.0.0.5", "10.0.0.5", ipv6="fe80::1").ssh_host() == "fe80::1"
    assert Device("10.0.0.5", "10.0.0.5").ssh_host() == "10.0.0.5"


def test_ssh_host_skips_a_known_hosts_name_that_isnt_a_valid_hostname():
    """Verify that Device.ssh_host applies the same hostname-shape check to a
    known_hosts name as smb_host applies to its own tiers, falling through to the
    next tier rather than returning something unusable - known_hosts entries are
    ordinarily always valid, but this guards the same way regardless."""
    device = Device("we rner", "10.0.0.5", names={"we rner": {"ssh-known-hosts"}, "werner": {"etc-hosts"}})

    assert device.ssh_host() == "werner"


@pytest.mark.parametrize("name", ["nas01", "nas-01.local", "NAS", "n1"])
def test_smb_host_accepts_ordinary_hostname_shaped_names(name):
    """Verify that Device.smb_host's hostname check isn't overly strict - plain
    alphanumeric names, hyphens, and dot-separated labels (the actual common case)
    are all accepted as-is."""
    device = Device(name, "10.0.0.5", names={name: {"WSD"}})

    assert device.smb_host() == name


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
