from argparse import Namespace

from .models import PacketEvent


def matches_filters(event: PacketEvent, args: Namespace) -> bool:
    if args.proto and event.protocol.upper() != args.proto.upper():
        return False

    if args.ip and args.ip not in (event.src_ip, event.dst_ip):
        return False

    if args.mac:
        mac = args.mac.lower()
        if mac not in (event.src_mac.lower(), event.dst_mac.lower()):
            return False

    return True
