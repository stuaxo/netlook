"""The headless --dump path: scan the network, fetch everything discoverable, and
write it as JSON with no GUI - shared by netlook (ui/dpg.py's --dump flag) rather
than being its own entry point, since the data being dumped is exactly the same
View Model (ui/base.py) both GUIs already build for themselves.
"""
from __future__ import annotations

import asyncio
import json
import sys

from .core.scanner import NetworkScanner
from .ui.base import build_device_row_view, build_devices_payload, save_devices_to_json

DEFAULT_SCAN_SECONDS = 10.0


async def dump(output: str | None, scan_seconds: float, scanner: NetworkScanner | None = None) -> None:
    # scanner is injectable (mirrors ui.textual.NetworkBrowserApp) so tests can pass
    # a hermetic one instead of touching the real network; real usage always omits
    # it and gets production discovery.
    scanner = scanner if scanner is not None else NetworkScanner()
    await scanner.start()
    try:
        await asyncio.sleep(scan_seconds)
        await scanner.wait_idle()  # let any probe still in flight when the timer fired land

        # Expanding every device (build_device_row_view(..., expanded=True)) is
        # what actually triggers a service's lazy fetch (samba's share list,
        # incus's instance list, ...) via scanner.ensure_fetched - see
        # ui/base.py. That call only *schedules* the fetch, so a second
        # wait_idle() is needed before rebuilding the views that capture its
        # result.
        devices = list(scanner.devices.values())
        for dev in devices:
            await build_device_row_view(dev, scanner, expanded=True)
        await scanner.wait_idle()

        views = [await build_device_row_view(dev, scanner, expanded=True) for dev in devices]
    finally:
        await scanner.close()

    # Default is stdout, not a file - --dump's natural use is piping straight into
    # jq or another script. Status goes to stderr in both cases, so the stdout
    # stream is always clean JSON and nothing else, whether or not --output is given.
    if output:
        save_devices_to_json(views, path=output)
        print(f"Saved {len(views)} device(s) to {output}", file=sys.stderr)
    else:
        json.dump(build_devices_payload(views), sys.stdout, indent=2)
        sys.stdout.write("\n")
        print(f"({len(views)} device(s))", file=sys.stderr)
