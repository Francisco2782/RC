from argparse import Namespace

from scapy.all import sniff

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
    finally:
        output.close()
