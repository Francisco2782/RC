from __future__ import annotations

from collections import Counter
from argparse import Namespace

from scapy.all import sniff
from scapy.error import Scapy_Exception

from .filters import matches_filters
from .output import OutputManager
from .parser import parse_packet


def run_capture(args: Namespace):
    output = OutputManager(live=args.live, log_path=args.log, log_format=args.format)
    request_states: dict[str, tuple[int, float]] = {}
    capture_counter = 0
    proto_counter = Counter()
    captured_events = []
    plot_kinds = getattr(args, "plots", None) or ([] if getattr(args, "plot", None) is None else [args.plot])

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
            request_states[correlation_key] = (event.capture_id, event.packet_time)
            event.summary = f"request(id={event.capture_id}) {src} -> {dst} | {event.summary}"
        elif message_type == "reply" and correlation_key:
            matched_request = request_states.get(correlation_key)
            matched_request_id = matched_request[0] if matched_request else None
            event.reply_to_id = matched_request_id
            if matched_request is not None:
                request_id, request_time = matched_request
                event.rtt_ms = max((event.packet_time - request_time) * 1000.0, 0.0)
                event.summary = (
                    f"reply(id={event.capture_id}) ao request(id={request_id}) "
                    f"{src} -> {dst} | RTT={event.rtt_ms:.3f} ms | {event.summary}"
                )
            else:
                event.summary = f"reply(id={event.capture_id}) sem request conhecido {src} -> {dst} | {event.summary}"
        else:
            event.summary = f"capture(id={event.capture_id}) {src} -> {dst} | {event.summary}"

        if matches_filters(packet, event, args):
            if args.proto and args.proto.upper() in {"IP", "IPV4"}:
                event.protocol = "IPv4"
            proto_counter[event.protocol] += 1
            captured_events.append(event)
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

        if plot_kinds:
            try:
                from .plots import plot_capture
            except ModuleNotFoundError as exc:
                if exc.name == "matplotlib":
                    print("[Erro] O módulo 'matplotlib' não está disponível. Instala-o para usar gráficos.")
                    return
                raise

            for kind in plot_kinds:
                try:
                    prefix = f"capture_{args.iface}_{len(captured_events)}pkts"
                    plot_capture(captured_events, kind, getattr(args, "plot_dir", None), filename_prefix=prefix)
                except ValueError as exc:
                    print(f"[Erro] {exc}")