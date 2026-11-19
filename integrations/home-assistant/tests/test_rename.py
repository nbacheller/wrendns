"""REQ: DOC-006, API-013 (T33.2, ADR-1028, ADR-1030) -- the integration under its new name.

These checks read files only (no Home Assistant, no node), so they also run without the test harness:
`pytest --noconftest tests/test_rename.py`.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
COMPONENT = HERE / "custom_components" / "wrendns"


def _const(name: str) -> str:
    for line in (COMPONENT / "const.py").read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}:"):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError(f"{name} not in const.py")


def test_the_domain_is_wrendns_everywhere() -> None:
    manifest = json.loads((COMPONENT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["domain"] == "wrendns"
    assert manifest["name"] == "WrenDNS"
    assert _const("DOMAIN") == "wrendns"
    assert COMPONENT.name == "wrendns"
    assert not (HERE / "custom_components" / "telltale").exists(), "the old folder is gone"


def test_events_and_actions_carry_the_new_name() -> None:
    assert _const("EVENT_ANOMALY") == "wrendns_anomaly"
    services = (COMPONENT / "services.yaml").read_text(encoding="utf-8")
    for action in ("pause_blocking", "resume_blocking", "quarantine_device", "release_device", "acknowledge_anomalies"):
        assert f"{action}:" in services


def test_no_old_name_is_left_except_the_compatibility_shim_and_the_changelog() -> None:
    allowed = {COMPONENT / "legacy.py"}
    for path in HERE.rglob("*"):
        if not path.is_file() or path in allowed or path.name == "CHANGELOG.md" or path == Path(__file__):
            continue
        if path.suffix not in {".py", ".json", ".yaml", ".md", ".toml", ".ini"}:
            continue
        text = path.read_text(encoding="utf-8").lower()
        assert "telltale" not in text, f"{path.relative_to(HERE)} still says telltale"


def test_both_header_spellings_are_sent() -> None:
    api = (COMPONENT / "api.py").read_text(encoding="utf-8")
    assert '"X-Wrendns-Reason"' in api and "LEGACY_REASON_HEADER" in api
    assert '"X-Wrendns-Client"' in api and "LEGACY_CLIENT_HEADER" in api
    legacy = (COMPONENT / "legacy.py").read_text(encoding="utf-8")
    assert '"X-Telltale-Reason"' in legacy and '"X-Telltale-Client"' in legacy


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path.name} isn't a PNG"
    return struct.unpack(">II", data[16:24])


def test_the_icons_are_the_brand_files() -> None:
    icon = COMPONENT / "brand" / "icon.png"
    icon2x = COMPONENT / "brand" / "icon@2x.png"
    assert _png_size(icon) == (256, 256)
    assert _png_size(icon2x) == (512, 512)
    assert icon.read_bytes() == (ROOT / "brand" / "logos" / "wrendns-icon-256.png").read_bytes()
    assert icon2x.read_bytes() == (ROOT / "brand" / "logos" / "wrendns-icon-512.png").read_bytes()


def test_the_changelog_says_what_breaks_and_how_to_migrate() -> None:
    text = (HERE / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "(breaking)" in text
    for needle in ("telltale_anomaly", "wrendns_anomaly", "custom_components/telltale", "Migrating", "Delete"):
        assert needle in text
    assert json.loads((COMPONENT / "manifest.json").read_text(encoding="utf-8"))["version"] == "0.2.0"
    assert text.index("## 0.2.0") < text.index("## 0.1.0")
