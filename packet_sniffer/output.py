import csv
import json
from pathlib import Path

from .models import PacketEvent


class OutputManager:
    def __init__(self, live: bool, log_path: str | None = None, log_format: str = "json"):
        self.live = live
        self.log_path = Path(log_path) if log_path else None
        self.log_format = log_format
        self._csv_writer = None
        self._csv_file = None

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            if self.log_format == "csv":
                self._csv_file = self.log_path.open("w", newline="", encoding="utf-8")
                self._csv_writer = csv.DictWriter(
                    self._csv_file,
                    fieldnames=[
                        "timestamp",
                        "interface",
                        "protocol",
                        "src_mac",
                        "dst_mac",
                        "src_ip",
                        "dst_ip",
                        "size",
                        "summary",
                        "exchange",
                    ],
                )
                self._csv_writer.writeheader()

    def close(self):
        if self._csv_file:
            self._csv_file.close()

    def write(self, event: PacketEvent):
        if self.live:
            exchange_suffix = f" | {event.exchange}" if event.exchange else ""
            print(
                f"[{event.timestamp}] {event.interface} {event.protocol:<6} "
                f"{event.src_ip} -> {event.dst_ip} "
                f"({event.size}B) {event.summary}{exchange_suffix}"
            )

        if not self.log_path:
            return

        payload = event.to_dict()
        if self.log_format == "json":
            with self.log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
        elif self.log_format == "txt":
            with self.log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(
                    f"[{event.timestamp}] {event.interface} {event.protocol} "
                    f"{event.src_ip}->{event.dst_ip} {event.size}B {event.summary}"
                    f" {'| ' + event.exchange if event.exchange else ''}\n"
                )
        elif self.log_format == "csv" and self._csv_writer:
            self._csv_writer.writerow(payload)
            self._csv_file.flush()
