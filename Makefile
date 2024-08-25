run_tests:
	python -m unittest discover

flake:
	flake8

type-check:
	mypy ./ext4 --strict

clean:
	rm -rf .mypy_cache
	rm -rf build
	rm -rf dist
	rm -f coverage.xml
	rm -f .coverage

test: run_tests flake type-check

install:
	pip install -U setuptools wheel build
	pip install -U -e .[dev]
