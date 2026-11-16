.PHONY: install test lint golden-set eval eval-full serve

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

lint:
	ruff check src/ tests/

golden-set:
	python -m src.data.build_golden_set

eval:
	python -m src.eval.run_eval --split dev

eval-full:
	python -m src.eval.run_eval --split full

serve:
	uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
