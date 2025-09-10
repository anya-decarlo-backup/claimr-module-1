#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Convert a staging carrier.yaml into a single NDJSON row in data/carriers/carriers.jsonl.

Usage:
  python tools/stage_to_ndjson.py --carrier staging/2025-09/unitedhealth/carrier.yaml
  python tools/stage_to_ndjson.py --carrier <path> --output data/carriers/carriers.jsonl --dry-run
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from datetime import date

try:
    import yaml  # PyYAML
except Exception as e:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# --- Schema-whitelist (keep this aligned with schema/carrier.schema.json) ---
TOP_LEVEL_FIELDS = {
    "id", "name", "brand", "naic", "tin",
    "categories", "parent_id", "subsidiary_ids", "scope",
    "payer_edi_ids", "_meta"
}
PAYER_EDI_FIELDS = {"id", "clearinghouse", "transactions"}
META_FIELDS = {"source", "last_verified_at", "note"}

def stable_carrier_id(name: str, brand: str, prefix: str = "crr_") -> str:
    """Deterministic, opaque ID based on normalized name|brand (stable across runs)."""
    key = f"{(name or '').strip().lower()}|{(brand or '').strip().lower()}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}{digest}"

def sanitize_carrier(obj: dict) -> dict:
    """Strip unknown fields and coerce shapes to match schema."""
    if not isinstance(obj, dict):
        raise ValueError("carrier.yaml must contain a single YAML mapping (key/value object).")

    # Keep only known top-level fields
    cleaned = {k: v for k, v in obj.items() if k in TOP_LEVEL_FIELDS}

    # Required-ish fields (we won't fabricate them silently)
    for req in ("name", "brand", "categories", "scope", "_meta"):
        if req not in cleaned or cleaned[req] in (None, [], ""):
            raise ValueError(f"Missing required field '{req}' in carrier.yaml")

    # Normalize simple types
    cleaned.setdefault("id", None)
    cleaned.setdefault("naic", None)
    cleaned.setdefault("tin", None)
    cleaned.setdefault("parent_id", None)
    cleaned.setdefault("subsidiary_ids", [])
    cleaned.setdefault("payer_edi_ids", [])

    # List coercions
    for list_key in ("categories", "subsidiary_ids", "scope", "payer_edi_ids"):
        if cleaned.get(list_key) is None:
            cleaned[list_key] = []
        if list_key != "payer_edi_ids" and not isinstance(cleaned[list_key], list):
            raise ValueError(f"Field '{list_key}' must be a list")

    # payer_edi_ids item shape
    edi_items = []
    for item in cleaned["payer_edi_ids"]:
        if not isinstance(item, dict):
            raise ValueError("Each item in 'payer_edi_ids' must be an object")
        edi_items.append({k: item.get(k, None) for k in PAYER_EDI_FIELDS})
    cleaned["payer_edi_ids"] = edi_items

    # _meta shape
    meta = cleaned["_meta"]
    if not isinstance(meta, dict):
        raise ValueError("'_meta' must be an object")
    meta_clean = {k: meta.get(k, None) for k in META_FIELDS}

    # Enforce meta minimums
    if not meta_clean.get("source"):
        raise ValueError("'_meta.source' is required (path or url to your evidence)")
    if not meta_clean.get("last_verified_at"):
        # We prefer explicit dates, but default to today if omitted
        meta_clean["last_verified_at"] = date.today().isoformat()
    cleaned["_meta"] = meta_clean

    return cleaned

def read_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        raise ValueError("carrier.yaml is empty")
    if isinstance(data, list):
        if len(data) != 1:
            raise ValueError("carrier.yaml should define a single carrier object, not a list")
        data = data[0]
    if not isinstance(data, dict):
        raise ValueError("carrier.yaml must contain a YAML object (mapping)")

    return data

def ensure_output_file(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()

def check_duplicate_id(output_path: Path, new_id: str):
    if not new_id:
        return
    with output_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("id") == new_id:
                raise ValueError(f"Duplicate id '{new_id}' found in {output_path}")

def main():
    ap = argparse.ArgumentParser(description="Convert carrier.yaml to NDJSON row")
    ap.add_argument("--carrier", required=True, help="Path to staging carrier.yaml")
    ap.add_argument("--output", default="data/carriers/carriers.jsonl", help="NDJSON output file")
    ap.add_argument("--id-prefix", default="crr_", help="Prefix for generated carrier IDs")
    ap.add_argument("--dry-run", action="store_true", help="Print JSON to stdout instead of appending")
    args = ap.parse_args()

    carrier_path = Path(args.carrier)
    out_path = Path(args.output)

    if not carrier_path.exists():
        print(f"ERROR: {carrier_path} does not exist", file=sys.stderr)
        sys.exit(2)

    try:
        raw = read_yaml(carrier_path)
        obj = sanitize_carrier(raw)
        # Generate stable id if missing/null
        if not obj.get("id"):
            obj["id"] = stable_carrier_id(obj["name"], obj["brand"], prefix=args.id_prefix)

        # Prepare output
        record = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

        if args.dry_run:
            print(record)
            return

        ensure_output_file(out_path)
        check_duplicate_id(out_path, obj["id"])

        with out_path.open("a", encoding="utf-8") as f:
            f.write(record + "\n")

        print(f"✓ Appended carrier {obj['id']} → {out_path}")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
