.PHONY: install-dev lint pre-commit-install

install-dev:
	python -m pip install -r requirements-dev.txt

lint:
	./scripts/run_pylint.sh

pre-commit-install:
	pre-commit install
