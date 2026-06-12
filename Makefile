.PHONY: test lint format

test:
	pytest tests/ -v

lint:
	flake8 .
	black --check .

format:
	black .
