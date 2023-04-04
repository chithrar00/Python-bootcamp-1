# Define virtual environment name
VENV := venv

# Set up environment configuration for virtual environment activation
ifndef VIRTUAL_ENV
	ACTIVATE := $(VENV)/bin/activate
else
	ACTIVATE := $(VIRTUAL_ENV)/bin/activate
endif

# Set default target to start
.DEFAULT_GOAL := start

.PHONY: init
init:
	# Create virtual environment
	python3 -m venv $(VENV)

	# Activate virtual environment and install requirements
	. "$(ACTIVATE)" && pip install -r requirements.txt

.PHONY: start
start:
	# Activate virtual environment and start uvicorn with 4 workers
	. "$(ACTIVATE)" && uvicorn main:app  --reload

.PHONY: clean
clean:
	# Remove virtual environment
	rm -rf $(VENV)

.PHONY: test
test:
	# Run unittest
	. "$(ACTIVATE)" && pytest --cov=./ --cov-report=html --cov-report=term -v test_main.py

.PHONY: report
report:
	# Open report in default browser
	open ./htmlcov/index.html
