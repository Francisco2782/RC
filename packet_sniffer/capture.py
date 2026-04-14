from argparse import Namespace

from scapy.all import sniff
from scapy.error import Scapy_Exception

from .filters import matches_filters
from .output import OutputManager
from .parser import parse_packet


def run_capture(args: Namespace):
    output = OutputManager(live=args.live, log_path=args.log, log_format=args.format)

    def handle_packet(packet):
        event = parse_packet(packet, args.iface)
        if matches_filters(event, args):
            output.write(event)

    try:
        sniff(
            iface=args.iface,
            filter=args.bpf,
            prn=handle_packet,
            store=False,
            count=args.count,
        )
    except PermissionError as exc:
        raise RuntimeError(
            "Permissão insuficiente para capturar pacotes. Execute com sudo/root."
        ) from exc
    except Scapy_Exception as exc:
        raise RuntimeError(
            f"Erro de captura na interface '{args.iface}'. Confirme o nome com 'ip -br link'."
        ) from exc
    except ValueError as exc:
        raise RuntimeError(
            f"Interface '{args.iface}' não encontrada. Verifique com 'ip -br link' e use uma interface válida."
        ) from exc
    finally:
        output.close()
