#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Packet Sniffer MVP (RC TP2)")
    parser.add_argument("--iface", required=True, help="Interface de rede (ex: eth0, wlan0)")
    parser.add_argument("--proto", help="Filtro por protocolo (ARP, IPv4, ICMP, TCP, UDP, DHCP, DNS)")
    parser.add_argument("--ip", help="Filtro por IP (origem ou destino)")
    parser.add_argument("--mac", help="Filtro por MAC (origem ou destino)")
    parser.add_argument("--bpf", default="", help="Expressão BPF (ex: 'icmp or arp')")
    parser.add_argument("--live", action="store_true", help="Mostrar em tempo real na consola")
    parser.add_argument("--log", help="Caminho do ficheiro de log")
    parser.add_argument(
        "--format",
        choices=["txt", "csv", "json"],
        default="json",
        help="Formato do log quando --log está ativo",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Número de pacotes a capturar (0 = infinito)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.live and not args.log:
        args.live = True

    if os.geteuid() != 0:
        print("[Aviso] Captura em interface real normalmente exige permissões root.")

    try:
        from packet_sniffer import run_capture
    except ModuleNotFoundError as error:
        if error.name == "scapy":
            venv_python = Path(__file__).resolve().parent / ".venv" / "bin" / "python"
            if venv_python.exists() and os.access(venv_python, os.X_OK):
                print("[Info] 'scapy' não encontrado neste Python. A tentar relançar com .venv...")
                os.execv(str(venv_python), [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]])

            print("[Erro] O módulo 'scapy' não está disponível neste Python.")
            print("Use o interpretador da venv: sudo ./.venv/bin/python sniffer.py ...")
            raise SystemExit(1)
        raise

    try:
        run_capture(args)
    except RuntimeError as error:
        print(f"[Erro] {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
