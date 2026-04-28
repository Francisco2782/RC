#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Packet Sniffer MVP (RC TP2)")
    parser.add_argument("--iface", help="Interface de rede (ex: eth0, wlan0)")
    parser.add_argument("--menu", action="store_true", help="Abrir menu interativo no terminal")
    parser.add_argument("--proto", help="Filtro por protocolo (ARP, IPv4, ICMP, TCP, UDP, DHCP, DNS)")
    parser.add_argument("--ip", help="Filtro por IP (origem ou destino)")
    parser.add_argument("--mac", help="Filtro por MAC (origem ou destino)")
    parser.add_argument(
        "--hfilter",
        default="",
        help=(
            "Filtro de campos de cabeçalho (estilo Wireshark), "
            "ex: 'ip.src==10.0.0.2 and tcp.dstport==443'"
        ),
    )
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


def _get_interfaces() -> list[str]:
    import subprocess

    try:
        result = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            return [line.split()[0] for line in result.stdout.strip().splitlines() if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            names = []
            for line in result.stdout.splitlines():
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    names.append(line.split(":")[0])
            return names
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return []


def validate_interface(iface: str):
    ifaces = _get_interfaces()
    if not ifaces:
        print(f"[Aviso] Não foi possível validar interface '{iface}' (ambiente restrito?). Tentando capturar...")
        return

    iface_base = iface.split(":")[0]
    matching_ifaces = [i for i in ifaces if i.startswith(iface_base)]

    if not matching_ifaces:
        print(f"[Erro] Interface '{iface}' não encontrada.")
        print(f"Interfaces disponíveis: {', '.join(ifaces)}")
        raise SystemExit(1)


def _read_choice(prompt: str, valid: set[str] | None = None, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt).strip()
        if not value and allow_empty:
            return ""
        if valid is None or value in valid:
            return value
        print("[Erro] Opção inválida.")


def _read_text(prompt: str, allow_empty: bool = True) -> str:
    while True:
        value = input(prompt).strip()
        if value or allow_empty:
            return value
        print("[Erro] Valor inválido.")


def _choose_interface() -> str:
    ifaces = _get_interfaces()
    if not ifaces:
        return _read_text("Interface (ex: eth0): ", allow_empty=False)

    print("\n┌─────────────────────────────────┐")
    print("│     Interfaces disponíveis      │")
    print("├─────────────────────────────────┤")
    for index, iface in enumerate(ifaces, start=1):
        print(f"│ {index}) {iface:<29}│")
    print("│  0) Escrever manualmente        │")
    print("└─────────────────────────────────┘")

    while True:
        choice = _read_choice("Escolhe a interface: ", allow_empty=False)
        if choice == "0":
            return _read_text("Escreve a interface: ", allow_empty=False)
        if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
            return ifaces[int(choice) - 1]
        print("[Erro] Opção inválida.")


def _print_banner(title: str) -> None:
    width = 34
    bar = "─" * width
    print(f"\n┌{bar}┐")
    print(f"│{title.center(width)}│")
    print(f"└{bar}┘")


def _choose_mode() -> tuple[bool, str | None, str]:
    while True:
        _print_banner(" MODO DE SAÍDA ")
        print("  1) Live na consola")
        print("  2) Só ficheiro de log")
        print("  3) Live + ficheiro de log")
        print("  ───────────────────────")
        print("  0) Voltar")

        choice = _read_choice("Escolhe o modo: ", valid={"0", "1", "2", "3"})
        if choice == "0":
            raise IndexError
        if choice == "1":
            return True, None, "json"
        if choice == "2":
            fmt = _choose_format()
            log_path = f"logs/capture.{fmt}"
            print(f"\n[Info] Sem live: estás a escrever em {log_path}")
            return False, log_path, fmt

        fmt = _choose_format()
        log_path = f"logs/capture.{fmt}"
        print(f"\n[Info] Live + log: estás a escrever em {log_path}")
        return True, log_path, fmt


def _choose_format() -> str:
    _print_banner(" FORMATO DO LOG ")
    print("  1) json")
    print("  2) csv")
    print("  3) txt")
    choice = _read_choice("Escolhe o formato: ", valid={"1", "2", "3"})
    return {"1": "json", "2": "csv", "3": "txt"}[choice]


def _choose_capture_style() -> str:
    while True:
        _print_banner(" TIPO DE CAPTURA ")
        print("  1) Sem filtros")
        print("  2) Com filtros")
        print("  ───────────────────────")
        print("  0) Voltar")

        choice = _read_choice("Escolhe uma opção: ", valid={"0", "1", "2"})
        if choice == "1":
            return "nofilters"
        if choice == "2":
            return "filters"
        raise IndexError


def _choose_protocol() -> str | None:
    while True:
        _print_banner(" FILTRO POR PROTOCOLO ")
        print("  1) ARP")
        print("  2) IPv4")
        print("  3) ICMP")
        print("  4) TCP")
        print("  5) UDP")
        print("  6) DHCP")
        print("  7) DNS")
        print("  ───────────────────────")
        print("  0) Voltar")
        choice = _read_choice("Escolhe o protocolo: ", valid={"0", "1", "2", "3", "4", "5", "6", "7"})
        if choice == "0":
            raise IndexError
        return {
            "1": "ARP",
            "2": "IPv4",
            "3": "ICMP",
            "4": "TCP",
            "5": "UDP",
            "6": "DHCP",
            "7": "DNS",
        }[choice]


def _choose_filters(args: argparse.Namespace) -> argparse.Namespace:
    current = argparse.Namespace(**vars(args))

    while True:
        _print_banner(" FILTROS DISPONÍVEIS ")
        print("  1) Protocolo")
        print("  2) IP")
        print("  3) MAC")
        print("  4) BPF")
        print("  5) hfilter")
        print("  ───────────────────────")
        print("  6) Limpar filtros")
        print("  7) Ver resumo")
        print("  ───────────────────────")
        print("  8) Iniciar captura")
        print("  0) Voltar")

        choice = _read_choice("Escolhe uma opção: ", valid={"0", "1", "2", "3", "4", "5", "6", "7", "8"})

        if choice == "0":
            raise IndexError
        if choice == "1":
            try:
                current.proto = _choose_protocol()
            except IndexError:
                continue
        elif choice == "2":
            current.ip = _read_text("IP (ENTER para limpar): ") or None
        elif choice == "3":
            current.mac = _read_text("MAC (ENTER para limpar): ") or None
        elif choice == "4":
            current.bpf = _read_text("Expressão BPF (ENTER para limpar): ")
        elif choice == "5":
            current.hfilter = _read_text("Expressão hfilter (ENTER para limpar): ")
        elif choice == "6":
            current.proto = None
            current.ip = None
            current.mac = None
            current.hfilter = ""
            current.bpf = ""
            current.count = 0
        elif choice == "7":
            print("\n┌──────────────┬──────────────────┐")
            print("│    Resumo    │                  │")
            print("├──────────────┼──────────────────┤")
            print(f"│ Interface    │ {current.iface or '-':<16} │")
            print(f"│ Live         │ {'sim' if current.live else 'não':<16} │")
            print(f"│ Log          │ {current.log or '-':<16} │")
            print(f"│ Formato      │ {current.format:<16} │")
            print("├──────────────┼──────────────────┤")
            print(f"│ Proto        │ {current.proto or '-':<16} │")
            print(f"│ IP           │ {current.ip or '-':<16} │")
            print(f"│ MAC          │ {current.mac or '-':<16} │")
            print(f"│ BPF          │ {current.bpf or '-':<16} │")
            print(f"│ HFilter      │ {current.hfilter or '-':<16} │")
            print(f"│ Count        │ {current.count:<16} │")
            print("└──────────────┴──────────────────┘")
            input("\nPrima ENTER para voltar ao menu...")
        elif choice == "8":
            return current


def _print_start_screen(args: argparse.Namespace) -> None:
    _print_banner(" INICIAR CAPTURA ")
    print(f"  Interface : {args.iface}")
    print(f"  Live      : {'sim' if args.live else 'não'}")
    print(f"  Log       : {args.log or '-'}")
    print(f"  Formato   : {args.format}")
    print(f"  Proto     : {args.proto or '-'}")
    print(f"  IP        : {args.ip or '-'}")
    print(f"  MAC       : {args.mac or '-'}")
    print(f"  BPF       : {args.bpf or '-'}")
    print(f"  HFilter   : {args.hfilter or '-'}")
    print(f"  Count     : {args.count}")
    print("\n" + "─" * 36)
    print("  8) INICIAR CAPTURA AGORA")
    print("  0) VOLTAR ATRÁS")
    print("─" * 36)


def _interactive_menu(args: argparse.Namespace) -> argparse.Namespace:
    current = argparse.Namespace(**vars(args))

    print("\n╔══════════════════════════════╗\n║    Packet Sniffer  RC TP2    ║\n╚══════════════════════════════╝")


    while not current.iface:
        try:
            current.iface = _choose_interface()
        except IndexError:
            continue

    while True:
        try:
            current.live, current.log, current.format = _choose_mode()
            print(f"\n[Estado] Saída definida: {'live' if current.live else 'log'} | {current.log or 'sem ficheiro'} | {current.format}")
            break
        except IndexError:
            current.iface = ""
            while not current.iface:
                try:
                    current.iface = _choose_interface()
                except IndexError:
                    continue

    while True:
        try:
            style = _choose_capture_style()
        except IndexError:
            try:
                current.live, current.log, current.format = _choose_mode()
                print(f"\n[Estado] Saída definida: {'live' if current.live else 'log'} | {current.log or 'sem ficheiro'} | {current.format}")
            except IndexError:
                current.iface = ""
                while not current.iface:
                    try:
                        current.iface = _choose_interface()
                    except IndexError:
                        continue
            continue

        if style == "nofilters":
            current.proto = None
            current.ip = None
            current.mac = None
            current.hfilter = ""
            current.bpf = ""
            current.count = 0
            print("\n[Estado] Captura sem filtros selecionada.")
            return current

        while True:
            try:
                current = _choose_filters(current)
                break
            except IndexError:
                break

        if current is None:
            continue

        print("\n[Estado] Captura com filtros selecionada.")
        print(f"[Estado] Proto={current.proto or '-'} | IP={current.ip or '-'} | MAC={current.mac or '-'} | BPF={current.bpf or '-'} | HFilter={current.hfilter or '-'}")
        return current


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.menu or not args.iface:
        args = _interactive_menu(args)

    if not args.live and not args.log:
        args.live = True

    if not args.iface:
        parser.error("--iface é obrigatório fora do modo interativo")

    validate_interface(args.iface)

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