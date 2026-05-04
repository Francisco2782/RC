.PHONY: help menu live log clean

PYTHON := ./.venv/bin/python
APP := sniffer.py
DEFAULT_IFACE ?= wlp60s0
LOG ?= logs/capture.json
FORMAT ?= json

help:
	@echo "Targets:"
	@echo "  make menu                 - abrir o menu interativo"
	@echo "  make clean                - remover logs gerados"

menu:
	sudo $(PYTHON) $(APP) --menu

clean:
	sudo rm -f logs/*.json logs/*.csv logs/*.txt logs/plots/*.png
