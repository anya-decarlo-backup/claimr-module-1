# claimr-payers Makefile

.PHONY: validate build clean

validate:
	python3 tools/validate.py

build:
	python3 tools/build_sqlite.py

clean:
	rm -rf __pycache__ *.sqlite *.parquet
