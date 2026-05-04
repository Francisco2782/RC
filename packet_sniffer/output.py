import json
import csv
from datetime import datetime


class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


class OutputManager:
    def __init__(
        self,
        live=True,
        log_path=None,
        log_format="json",
        txt_file=None,
        json_file=None,
        csv_file=None,
    ):
        self.live = live

        if log_path:
            if log_format == "txt":
                txt_file = log_path
            elif log_format == "json":
                json_file = log_path
            elif log_format == "csv":
                csv_file = log_path

        self.txt = open(txt_file, "w") if txt_file else None
        self.json = open(json_file, "w") if json_file else None
        self.csv = open(csv_file, "w", newline="") if csv_file else None

        self.json_data = []

        if self.csv:
            self.writer = csv.writer(self.csv)
            self.writer.writerow(
                [
                    "time",
                    "protocol",
                    "src_ip",
                    "dst_ip",
                    "summary",
                ]
            )

        if self.live:
            self.print_header()

    def print_header(self):
        print(
            Colors.WHITE
            + f"{'TIME':<10} {'SOURCE':<18} {'DESTINATION':<18} {'PROTO':<8} {'RTT(ms)':<10} INFO"
            + Colors.RESET
        )
        print("-" * 80)

    def get_color(self, protocol):
        table = {
            "TCP": Colors.BLUE,
            "UDP": Colors.CYAN,
            "HTTP": Colors.GREEN,
            "DNS": Colors.MAGENTA,
            "ICMP": Colors.YELLOW,
            "ARP": Colors.WHITE,
            "DHCP": Colors.RED,
            "IPv6": Colors.YELLOW,
        }

        return table.get(protocol, Colors.WHITE)

    def write(self, event):
        now = datetime.now().strftime("%H:%M:%S")

        src = event.src_ip if event.src_ip else "-"
        dst = event.dst_ip if event.dst_ip else "-"
        rtt = f"{event.rtt_ms:.3f}" if event.rtt_ms is not None else "-"

        line = f"{now:<10} {src:<18} {dst:<18} {event.protocol:<8} {rtt:<10} {event.summary}"

        if self.live:
            color = self.get_color(event.protocol)
            print(color + line + Colors.RESET)

        if self.txt:
            self.txt.write(line + "\n")

        if self.json:
            self.json_data.append(
                {
                    "time": now,
                    "protocol": event.protocol,
                    "src_ip": src,
                    "dst_ip": dst,
                    "rtt_ms": event.rtt_ms,
                    "summary": event.summary,
                }
            )

        if self.csv:
            self.writer.writerow(
                [
                    now,
                    event.protocol,
                    src,
                    dst,
                    rtt,
                    event.summary,
                ]
            )

    def print_stats(self, counter):
        if not self.live:
            return

        print("\n--- Estatísticas ---")

        for proto, count in sorted(counter.items(), key=lambda x: -x[1]):
            color = self.get_color(proto)
            print(color + f"{proto:<10}: {count}" + Colors.RESET)

    def close(self):
        if self.txt:
            self.txt.close()

        if self.json:
            json.dump(self.json_data, self.json, indent=4)
            self.json.close()

        if self.csv:
            self.csv.close()