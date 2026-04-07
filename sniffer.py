#!/usr/bin/env python3
import argparse
import os

from packet_sniffer import run_capture


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

    run_capture(args)


if __name__ == "__main__":
    main()
