from collections import Counter
from argparse import Namespace

from scapy.all import sniff
from scapy.error import Scapy_Exception

from .filters import matches_filters
from .output import OutputManager
from .parser import parse_packet


def run_capture(args: Namespace):
    output = OutputManager(live=args.live, log_path=args.log, log_format=args.format)
    request_ids: dict[str, int] = {}
    capture_counter = 0
    proto_counter = Counter()

    def endpoint(ip: str, mac: str) -> str:
        return ip if ip != "-" else mac

    def handle_packet(packet):
        nonlocal capture_counter

        event, message_type, correlation_key = parse_packet(packet, args.iface)
        capture_counter += 1
        event.capture_id = capture_counter

        src = endpoint(event.src_ip, event.src_mac)
        dst = endpoint(event.dst_ip, event.dst_mac)

        if message_type == "request" and correlation_key:
            request_ids[correlation_key] = event.capture_id
            event.summary = f"request(id={event.capture_id}) {src} -> {dst} | {event.summary}"
        elif message_type == "reply" and correlation_key:
            matched_request_id = request_ids.get(correlation_key)
            event.reply_to_id = matched_request_id
            if matched_request_id is not None:
                event.summary = (
                    f"reply(id={event.capture_id}) ao request(id={matched_request_id}) "
                    f"{src} -> {dst} | {event.summary}"
                )
            else:
                event.summary = f"reply(id={event.capture_id}) sem request conhecido {src} -> {dst} | {event.summary}"
        else:
            event.summary = f"capture(id={event.capture_id}) {src} -> {dst} | {event.summary}"

        if matches_filters(packet, event, args):
            proto_counter[event.protocol] += 1
            output.write(event)

    try:
        sniff(
            iface=args.iface,
            filter=args.bpf,
            prn=handle_packet,
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("\n[Info] Captura interrompida pelo utilizador.")
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
        output.print_stats(proto_counter)
        output.close()