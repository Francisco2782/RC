from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt


def _safe_stem(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def _label_for_kind(kind: str) -> str:
    return {
        "protocols": "protocolos",
        "traffic": "trafego",
        "rtt": "rtt_icmp",
        "sizes": "tamanho_pacotes",
    }.get(kind, kind)


def _bucket_packets(events, bucket_seconds: int = 1):
    if not events:
        return [], []

    start = min(event.packet_time for event in events)
    buckets: Counter[int] = Counter()

    for event in events:
        bucket = int((event.packet_time - start) // bucket_seconds)
        buckets[bucket] += 1

    xs = [start + bucket * bucket_seconds for bucket in sorted(buckets)]
    ys = [buckets[bucket] for bucket in sorted(buckets)]
    labels = [datetime.fromtimestamp(ts).strftime("%H:%M:%S") for ts in xs]
    return labels, ys


DEFAULT_PLOT_DIR = Path("logs/plots")


def _save_plot(fig, plot_kind: str, output_dir: str | None, filename_prefix: str | None = None):
    directory = Path(output_dir) if output_dir else DEFAULT_PLOT_DIR
    directory.mkdir(parents=True, exist_ok=True)

    prefix = _safe_stem(filename_prefix) + "_" if filename_prefix else ""
    filename = f"{prefix}{_label_for_kind(plot_kind)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    target = directory / filename
    fig.savefig(target, dpi=150, bbox_inches="tight")
    print(f"[Info] Gráfico guardado em {target}")


def plot_capture(events, plot_kind: str, output_dir: str | None = None, filename_prefix: str | None = None):
    if not events:
        print("[Info] Sem pacotes suficientes para gerar gráficos.")
        return

    kind = plot_kind.lower()

    if kind == "protocols":
        counts = Counter(event.protocol for event in events)
        labels = list(counts.keys())
        values = [counts[label] for label in labels]

        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.bar(labels, values, color="#4C78A8")
        ax.set_title("Distribuição por protocolo")
        ax.set_xlabel("Protocolo")
        ax.set_ylabel("Número de pacotes")
        ax.grid(axis="y", alpha=0.25)

    elif kind == "traffic":
        labels, values = _bucket_packets(events)
        fig, ax = plt.subplots(figsize=(9, 4.5))
        ax.plot(labels, values, marker="o", color="#F58518")
        ax.set_title("Pacotes por segundo")
        ax.set_xlabel("Tempo")
        ax.set_ylabel("Pacotes")
        ax.grid(alpha=0.25)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

    elif kind == "rtt":
        points = [(event.timestamp, event.rtt_ms) for event in events if event.rtt_ms is not None]
        if not points:
            print("[Info] Não foram encontrados RTTs para plotar.")
            return

        xs = [timestamp for timestamp, _ in points]
        ys = [rtt for _, rtt in points]
        fig, ax = plt.subplots(figsize=(9, 4.5))
        ax.plot(xs, ys, marker="o", color="#E45756")
        ax.set_title("RTT dos replies ICMP")
        ax.set_xlabel("Timestamp")
        ax.set_ylabel("RTT (ms)")
        ax.grid(alpha=0.25)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

    elif kind == "sizes":
        sizes = [event.size for event in events]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.hist(sizes, bins=min(20, max(5, len(set(sizes)))), color="#72B7B2", edgecolor="white")
        ax.set_title("Distribuição do tamanho dos pacotes")
        ax.set_xlabel("Tamanho (bytes)")
        ax.set_ylabel("Frequência")
        ax.grid(axis="y", alpha=0.25)

    else:
        raise ValueError(f"Tipo de gráfico inválido: {plot_kind}")

    fig.tight_layout()
    _save_plot(fig, kind, output_dir, filename_prefix=filename_prefix)
    plt.close(fig)