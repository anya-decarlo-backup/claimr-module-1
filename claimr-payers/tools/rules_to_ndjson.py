#!/usr/bin/env python3
"""
Convert a staging rules YAML file (list of rules) into NDJSON.

Examples:
  # Prior auth rules for a specific carrier, append to canonical path:
  python tools/rules_to_ndjson.py \
    --kind prior_auth \
    --rules staging/2025-09/unitedhealth/rules.prior_auth.yaml \
    --carrier-id crr_abcdef123456

  # Or write to an explicit output file:
  python tools/rules_to_ndjson.py \
    --kind prior_auth \
    --rules staging/2025-09/unitedhealth/rules.prior_auth.yaml \
    --output data/rules/by_carrier/crr_abcdef123456/prior_auth.jsonl

  # Dry run to inspect JSON:
  python tools/rules_to_ndjson.py --kind prior_auth --rules path.yaml --carrier-id crr_xxx --dry-run
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
from datetime import date

try:
    import yaml  # PyYAML
except Exception:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ALLOWED_KINDS = {"prior_auth":"prior_auth.jsonl",
                 "coverage":"coverage.jsonl",
                 "payment_edits":"payment_edits.jsonl",
                 "exclusions":"exclusions.jsonl"}

ALLOWED_RULE_TYPES = {"EDIT","PRIOR_AUTH","EXCLUSION","EXPERIMENTAL_INVESTIGATIONAL","POSTPAY_AUDIT"}

# Whitelists aligned to rule.schema.json (keeps inputs clean)
TOP_LEVEL_FIELDS = {
    "id","type","scope","service_ref","conditions","logic","precedence",
    "effective_start","effective_end","policy_refs","_meta",
    "cob_applicability","requires_primary_eob","secondary_parameters"
}
SCOPE_FIELDS = {"carrier_id","contract_id","plan_id","lob","state","plan_type","market"}
SERVICE_REF_FIELDS = {"service_id","cpt","hcpcs","drg","rev"}
CONDITIONS_BLOCKS = {"any_of","all_of","none_of"}
COND_FIELDS = {
    "has_flag","dx_in_value_set","dx_in_history_value_set","history_lookback_days",
    "min_age","max_age","sex","pos_in","utilization_gte","requires_prior_treatment",
    "excludes_value_set"
}
META_FIELDS = {"source","last_verified_at","note"}

def load_yaml_list(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path} must be a YAML list of rule objects")
    return data

def stable_rule_id(rule: dict, prefix="rule_") -> str:
    """Deterministic id from salient fields (so re-runs don’t churn)."""
    scope = rule.get("scope") or {}
    sr = rule.get("service_ref") or {}
    parts = [
        rule.get("type",""),
        scope.get("carrier_id",""),
        scope.get("lob",""), scope.get("state",""), scope.get("plan_type",""), scope.get("market",""),
        (sr.get("service_id") or ""),
        ",".join((sr.get("cpt") or []) if isinstance(sr.get("cpt"), list) else []),
        ",".join((sr.get("hcpcs") or []) if isinstance(sr.get("hcpcs"), list) else []),
        rule.get("effective_start",""),
    ]
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}{digest}"

def sanitize_rule(obj: dict) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("Rule must be an object")

    # keep only known top-level fields
    cleaned = {k: v for k, v in obj.items() if k in TOP_LEVEL_FIELDS}

    # type
    rtype = cleaned.get("type")
    if not rtype or rtype not in ALLOWED_RULE_TYPES:
        raise ValueError(f"Rule 'type' is required and must be one of {sorted(ALLOWED_RULE_TYPES)}")

    # scope
    scope = cleaned.get("scope") or {}
    if not isinstance(scope, dict):
        raise ValueError("'scope' must be an object")
    cleaned["scope"] = {k: scope.get(k, None) for k in SCOPE_FIELDS}

    # service_ref: either service_id OR codes
    sr = cleaned.get("service_ref") or {}
    if not isinstance(sr, dict):
        raise ValueError("'service_ref' must be an object")
    # normalize into {service_id, codes{cpt,hcpcs,drg,rev}}
    service_id = sr.get("service_id")
    codes = {}
    for k in ("cpt","hcpcs","drg","rev"):
        val = sr.get(k)
        if val is not None:
            if not isinstance(val, list):
                raise ValueError(f"'service_ref.{k}' must be a list of strings")
            codes[k] = val
    cleaned["service_ref"] = {"service_id": service_id, **({"cpt":codes.get("cpt")} if "cpt" in codes else {}),
                                               **({"hcpcs":codes.get("hcpcs")} if "hcpcs" in codes else {}),
                                               **({"drg":codes.get("drg")} if "drg" in codes else {}),
                                               **({"rev":codes.get("rev")} if "rev" in codes else {})}
    if not service_id and not codes:
        raise ValueError("service_ref requires either 'service_id' or at least one code list (cpt/hcpcs/drg/rev)")

    # conditions
    conds_in = cleaned.get("conditions") or {}
    if not isinstance(conds_in, dict):
        raise ValueError("'conditions' must be an object")
    conds_out = {}
    for block in CONDITIONS_BLOCKS:
        if block in conds_in:
            arr = conds_in[block]
            if not isinstance(arr, list):
                raise ValueError(f"'conditions.{block}' must be an array")
            conds_out[block] = []
            for item in arr:
                if not isinstance(item, dict):
                    raise ValueError(f"Each condition in '{block}' must be an object")
                c = {k: item.get(k, None) for k in COND_FIELDS if k in item}
                # simple structure validations
                if "utilization_gte" in c and c["utilization_gte"] is not None and not isinstance(c["utilization_gte"], dict):
                    raise ValueError("utilization_gte must be an object of feature->integer")
                if c:
                    conds_out[block].append(c)
            if not conds_out[block]:
                del conds_out[block]
    cleaned["conditions"] = conds_out

    # logic
    logic = cleaned.get("logic") or {}
    if not isinstance(logic, dict):
        raise ValueError("'logic' must be an object")
    # at minimum, prefer an outcome for operational rules
    if "outcome" not in logic:
        # allow coverage rules without outcome if they’re constraints, but PA/edit/exclusion should specify outcome
        if rtype in {"PRIOR_AUTH","EXCLUSION","POSTPAY_AUDIT","EDIT"}:
            raise ValueError("'logic.outcome' is required for operational rule types")
    cleaned["logic"] = logic

    # precedence
    if "precedence" in cleaned:
        if cleaned["precedence"] is not None and not isinstance(cleaned["precedence"], int):
            raise ValueError("'precedence' must be an integer if provided")
    else:
        cleaned["precedence"] = 50

    # dates
    es = cleaned.get("effective_start")
    ee = cleaned.get("effective_end")
    if not es:
        cleaned["effective_start"] = date.today().replace(month=1, day=1).isoformat()
    if not ee:
        cleaned["effective_end"] = date.today().replace(month=12, day=31).isoformat()

    # policy_refs (optional array of {url,doc_type,version,retrieved_at})
    if "policy_refs" in cleaned and cleaned["policy_refs"] is not None:
        if not isinstance(cleaned["policy_refs"], list):
            raise ValueError("'policy_refs' must be an array when provided")

    # COB-specific optional fields
    # - cob_applicability: primary_only/secondary_only/any
    # - requires_primary_eob: bool
    # - secondary_parameters: {apply_after_adjustment_groups:[], honor_primary_denial_codes:[], allow_secondary_if_primary_noncovered:bool}
    # (No further coercion here; schema validation will catch mis-types in CI.)

    # meta
    meta = cleaned.get("_meta") or {}
    if not isinstance(meta, dict):
        raise ValueError("'_meta' must be an object")
    meta_out = {k: meta.get(k, None) for k in META_FIELDS}
    if not meta_out.get("source"):
        raise ValueError("'_meta.source' is required")
    if not meta_out.get("last_verified_at"):
        meta_out["last_verified_at"] = date.today().isoformat()
    cleaned["_meta"] = meta_out

    # id
    if not cleaned.get("id"):
        cleaned["id"] = stable_rule_id(cleaned)

    return cleaned

def ensure_output(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()

def check_duplicates(out_path: Path, rid: str):
    if not rid or not out_path.exists():
        return
    with out_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("id") == rid:
                raise ValueError(f"Duplicate rule id '{rid}' in {out_path}")

def main():
    ap = argparse.ArgumentParser(description="Convert rules YAML (list) to NDJSON")
    ap.add_argument("--rules", required=True, help="Path to rules YAML (list of rule objects)")
    ap.add_argument("--kind", required=True, choices=ALLOWED_KINDS.keys(), help="Rule kind (controls default output filename)")
    ap.add_argument("--carrier-id", help="Carrier id to build default output path under data/rules/by_carrier/<carrier-id>/")
    ap.add_argument("--output", help="Explicit output file (.jsonl). Overrides --carrier-id.")
    ap.add_argument("--dry-run", action="store_true", help="Print results to stdout instead of appending")
    args = ap.parse_args()

    rules_path = Path(args.rules)

    if args.output:
        out_path = Path(args.output)
    else:
        if not hasattr(args, "carrier_id") or not args.carrier_id:
            print("ERROR: Provide --output OR --carrier-id to determine where to write", file=sys.stderr)
            sys.exit(2)
        out_path = Path("data") / "rules" / "by_carrier" / args.carrier_id / ALLOWED_KINDS[args.kind]

    try:
        items = load_yaml_list(rules_path)
        if not items:
            print("No rules to write (empty YAML list).", file=sys.stderr)
            sys.exit(0)

        # sanitize all
        cleaned = [sanitize_rule(it) for it in items]

        if args.dry_run:
            for obj in cleaned:
                print(json.dumps(obj, separators=(',', ':'), ensure_ascii=False))
            sys.exit(0)

        ensure_output(out_path)

        with out_path.open("a", encoding="utf-8") as f:
            for obj in cleaned:
                check_duplicates(out_path, obj["id"])
                f.write(json.dumps(obj, separators=(',', ':'), ensure_ascii=False) + "\n")

        print(f"✓ Appended {len(cleaned)} rule(s) → {out_path}")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
