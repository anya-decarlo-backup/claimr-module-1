#!/usr/bin/env python3
"""
JSON Schema validation tool for claimr data files

Usage:
  python tools/validate.py --schema schema/carrier.schema.json --data data/carriers/carriers.jsonl
  python tools/validate.py --schema schema/rule.schema.json --data data/rules/by_carrier/*/prior_auth.jsonl
"""

import argparse
import json
import sys
from pathlib import Path
import jsonschema

def load_ndjson(path: Path):
    """Load NDJSON file, skipping example lines"""
    items = []
    if not path.exists():
        return items
    
    with path.open('r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or (line.startswith('{') and '"example"' in line):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"JSON decode error in {path}:{line_num}: {e}")
                sys.exit(1)
    return items

def validate_file(schema_path: Path, data_path: Path):
    """Validate a single data file against schema"""
    # Load schema
    with schema_path.open('r') as f:
        schema = json.load(f)
    
    # Load and validate data
    items = load_ndjson(data_path)
    errors = []
    
    for i, item in enumerate(items):
        try:
            jsonschema.validate(item, schema)
        except jsonschema.ValidationError as e:
            errors.append(f"Item {i+1}: {e.message}")
    
    return errors

def main():
    parser = argparse.ArgumentParser(description='Validate NDJSON data against JSON Schema')
    parser.add_argument('--schema', required=True, help='Path to JSON schema file')
    parser.add_argument('--data', required=True, help='Path to NDJSON data file')
    args = parser.parse_args()
    
    schema_path = Path(args.schema)
    data_path = Path(args.data)
    
    if not schema_path.exists():
        print(f"Schema file not found: {schema_path}")
        sys.exit(1)
    
    if not data_path.exists():
        print(f"Data file not found: {data_path}")
        sys.exit(1)
    
    errors = validate_file(schema_path, data_path)
    
    if errors:
        print(f"❌ Validation failed for {data_path}")
        for error in errors:
            print(f"  {error}")
        sys.exit(1)
    else:
        print(f"✅ Validation passed for {data_path}")

if __name__ == '__main__':
    main()
