.PHONY: help menu live log clean

PYTHON := ./.venv/bin/python
APP := sniffer.py
DEFAULT_IFACE ?= wlp60s0
LOG ?= logs/capture.json
FORMAT ?= json

help:
	@echo "Targets:"
	@echo "  make menu                 - abrir o menu interativo"
	@echo "  make live IFACE=eth0      - captura em live"
	@echo "  make log IFACE=eth0       - captura para ficheiro"
	@echo "  make clean                - remover logs gerados"

menu:
	sudo $(PYTHON) $(APP) --menu

live:
	sudo $(PYTHON) $(APP) --iface $(IFACE) --live

log:
	sudo $(PYTHON) $(APP) --iface $(IFACE) --log $(LOG) --format $(FORMAT)

clean:
	sudo rm -f logs/*.json logs/*.csv logs/*.txt
