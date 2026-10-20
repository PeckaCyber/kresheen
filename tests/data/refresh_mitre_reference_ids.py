"""Regenerates `mitre_reference_ids.json`, the pinned table of MITRE ATT&CK
technique ids, MITRE ATLAS technique ids (`AML.*`) and CWE ids that `tests/unit/test_threat_reference_ids.py` checks
every built-in threat rule against.

Run by hand (needs network; the tests themselves never do):

    python tests/data/refresh_mitre_reference_ids.py

Sources are MITRE's own machine-readable releases, not a third-party copy:
ATT&CK Enterprise STIX (github.com/mitre-attack/attack-stix-data), ATLAS
(github.com/mitre-atlas/atlas-data) and the CWE catalog XML
(cwe.mitre.org/data/xml/cwec_latest.xml.zip). Only id, name and
lifecycle status are kept. ATT&CK (R), ATLAS(TM) and CWE(TM) are
(c) The MITRE Corporation, used here under MITRE's published terms of use.

After refreshing, re-run the tests: a rule that cites a technique MITRE has
since revoked or deprecated will fail, which is the point.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from xml.etree import (
    ElementTree as ET,
)

import requests
import yaml

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ATLAS_DIST = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUT = Path(__file__).with_name("mitre_reference_ids.json")


def _fetch(url: str) -> bytes:
    assert url.startswith("https://"), url
    response = requests.get(url, timeout=120)
    response.raise_for_status()
    return response.content


def attack_table(bundle: dict) -> dict:
    collection = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    techniques: dict[str, dict[str, str]] = {}
    for obj in bundle["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ref is None:
            continue
        status = "revoked" if obj.get("revoked") else "deprecated" if obj.get("x_mitre_deprecated") else "active"
        techniques[ref["external_id"]] = {"name": obj["name"], "status": status}
    return {"version": collection["x_mitre_version"], "techniques": dict(sorted(techniques.items()))}


def atlas_table(document: dict) -> dict:
    techniques = {
        tech["id"]: {"name": tech["name"], "status": "active"} for tech in document["techniques"].values()
    }
    return {"version": document["collection"]["version"], "techniques": dict(sorted(techniques.items()))}


def cwe_table(xml_bytes: bytes) -> dict:
    root = ET.fromstring(xml_bytes)
    entries: dict[str, dict[str, str]] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in ("Weakness", "Category") and element.get("ID"):
            status = "deprecated" if element.get("Status") == "Deprecated" else "active"
            entries[f"CWE-{element.get('ID')}"] = {"name": element.get("Name", ""), "status": status}
    return {"version": root.get("Version", ""), "entries": dict(sorted(entries.items(), key=lambda kv: int(kv[0][4:])))}


def main() -> None:
    attack = attack_table(json.loads(_fetch(ATTACK_URL)))
    # ATLAS-latest.yaml is a one-line pointer to the dated release file.
    atlas_file = _fetch(ATLAS_DIST + "ATLAS-latest.yaml").decode().strip()
    atlas = atlas_table(yaml.safe_load(_fetch(ATLAS_DIST + atlas_file)))
    with zipfile.ZipFile(io.BytesIO(_fetch(CWE_URL))) as archive:
        cwe = cwe_table(archive.read(next(n for n in archive.namelist() if n.endswith(".xml"))))
    OUT.write_text(json.dumps({"attack": attack, "atlas": atlas, "cwe": cwe}, indent=1) + "\n")
    print(f"ATT&CK {attack['version']}: {len(attack['techniques'])} ids; ATLAS {atlas['version']}: {len(atlas['techniques'])} ids; CWE {cwe['version']}: {len(cwe['entries'])} ids -> {OUT}")


if __name__ == "__main__":
    main()
