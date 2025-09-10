#!/bin/bash
# Run all Big-6 carrier conversions to NDJSON
echo "Converting all Big-6 carrier.yaml files to data/carriers/carriers.jsonl..."

set -e

python3 tools/stage_to_ndjson.py --carrier staging/2025-09/unitedhealth/carrier.yaml
python3 tools/stage_to_ndjson.py --carrier staging/2025-09/elevance/carrier.yaml
python3 tools/stage_to_ndjson.py --carrier staging/2025-09/aetna/carrier.yaml
python3 tools/stage_to_ndjson.py --carrier staging/2025-09/cigna/carrier.yaml
python3 tools/stage_to_ndjson.py --carrier staging/2025-09/humana/carrier.yaml
python3 tools/stage_to_ndjson.py --carrier staging/2025-09/kaiser-permanente/carrier.yaml

echo "All carrier conversions complete."
