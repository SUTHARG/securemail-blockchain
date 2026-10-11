.PHONY: test-engine test-contracts test lint

test-engine:
	python -m pytest engine/tests

test-contracts:
	cd contracts && npm test

test: test-engine test-contracts

lint:
	python -m compileall engine
