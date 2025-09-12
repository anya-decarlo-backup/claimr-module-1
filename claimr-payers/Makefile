# claimr-payers Makefile

.PHONY: validate build clean

validate:
	python3 tools/validate.py --schema schema/carrier.schema.json --data data/carriers/carriers.jsonl
	python3 tools/validate.py --schema schema/code_system.schema.json --data data/valuesets/custom/v2025-09.jsonl

build:
	python3 tools/build_sqlite.py

clean:
	rm -rf __pycache__ *.sqlite *.parquet
