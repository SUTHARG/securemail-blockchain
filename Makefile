.PHONY: test-engine test-backend test-validator test-contracts test lint demo eval

test-engine:
	@echo "--- Collecting engine/tests ---"
	@python -m pytest engine/tests --collect-only -q
	python -m pytest engine/tests

test-backend:
	@echo "--- Collecting backend/tests ---"
	@python -m pytest backend/tests --collect-only -q
	python -m pytest backend/tests

test-validator:
	@echo "--- Collecting validator/tests ---"
	@python -m pytest validator/tests --collect-only -q
	python -m pytest validator/tests

test-contracts:
	@echo "--- Running contracts tests ---"
	cd contracts && npm test

test: test-engine test-backend test-validator test-contracts

lint:
	python -m compileall engine backend validator

demo:
	bash scripts/demo_full.sh

eval:
	python eval/run_all.py
