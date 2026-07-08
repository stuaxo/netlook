"""Unit tests for netlook.dump - the headless --dump path behind netlook."""
import json

from netlook.core.models import Device
from netlook.core.services import Incus
from netlook.dump import dump


async def test_dump_writes_a_json_file_with_every_currently_known_device(net_scanner, tmp_path):
    """Verify that dump() writes one JSON entry per device already known to the
    scanner, by pre-populating devices directly (bypassing real discovery/network
    probing, which net_scanner stubs out) and checking the written file. Checks a
    superset, not an exact match - dump() calls scanner.start() itself (matching
    real usage), which always pre-seeds a "localhost" entry for this machine."""
    output = tmp_path / "dump.json"
    net_scanner.devices["10.0.0.5"] = Device("MyNAS", "10.0.0.5")
    net_scanner.devices["10.0.0.6"] = Device("Printer", "10.0.0.6")

    await dump(str(output), scan_seconds=0, scanner=net_scanner)

    data = json.loads(output.read_text())
    assert "saved_at" in data
    assert {"MyNAS", "Printer"} <= {d["hostname"] for d in data["devices"]}


async def test_dump_captures_a_lazily_fetched_services_data(net_scanner, tmp_path, fake_http_connection):
    """Verify that dump() doesn't just dump whatever's already loaded - it expands
    every device first (triggering a service's lazy fetch, e.g. Incus's instance
    list) and waits for that fetch to land before writing, by faking the HTTP layer
    Incus.fetch calls out to and checking the written file has the real fetched
    instance, not an empty/loading placeholder."""
    output = tmp_path / "dump.json"
    payload = {"status_code": 200, "metadata": [{"name": "web", "status": "Running"}]}
    fake_http_connection(body=json.dumps(payload).encode())
    dev = Device("OLIVE", "10.0.0.7")
    dev.services["incus"] = Incus(kind="incus", ip="10.0.0.7", port=8443)
    net_scanner.devices["10.0.0.7"] = dev

    await dump(str(output), scan_seconds=0, scanner=net_scanner)

    data = json.loads(output.read_text())
    olive = next(d for d in data["devices"] if d["hostname"] == "OLIVE")
    vm_tab = next(t for t in olive["category_tabs"] if t["category"] == "Virtual Machines")
    action_labels = {a["label"] for e in vm_tab["entries"] for a in e["actions"]}
    assert "web (Running)" in action_labels


async def test_dump_prints_to_stdout_when_no_output_is_given(net_scanner, capsys):
    """Verify that dump()'s default (output=None, i.e. no --output given) is to
    print the JSON payload to stdout rather than writing a file - the natural
    default for a tool meant to be piped into jq or another script - and that the
    status message goes to stderr instead, so stdout stays exactly the JSON and
    nothing else."""
    net_scanner.devices["10.0.0.5"] = Device("MyNAS", "10.0.0.5")

    await dump(None, scan_seconds=0, scanner=net_scanner)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert {"MyNAS"} <= {d["hostname"] for d in data["devices"]}
    assert "device(s)" in captured.err
