import bisect
import gzip
import json

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import matplotlib.pyplot as plt
import scienceplots

plt.style.use("science")


def get_fontsize():
    return plt.rcParams["font.size"]


def set_fontsize(value):
    plt.rcParams["font.size"] = value


FILE_DIR = Path(__file__).resolve().parent
REPO_DIR = FILE_DIR.parent
EVAL_DIR = REPO_DIR.parent / "eval"  # FIX: currently, this needs to be manually changed depending on your file layout
DATA_DIR = EVAL_DIR / "data"
PROGRESS_PRESENTATION_DIR = EVAL_DIR / "progress-presentation" / "figures"

COLORS = ["#D81B60", "#1E88E5", "#FFC107", "#004D40"]

set_fontsize(16)


@dataclass
class FlentPlotOptions:
    key: str = "TCP upload"
    interval_start: int = 0
    interval_end: int = 20
    enforced_gbit_rate: float = 1.0
    show_bounds: bool = True
    show_avg: bool = True


@dataclass
class IPerf3PlotOptions:
    interval_width: float = 0.1
    test_end: float = 5
    remove_headers: bool = False
    send_gbit_rate: Optional[float] = None
    enforced_gbit_rate: float = 1.0


@dataclass
class ExplorePlotOptions:
    flent_files: List[Path] = field(default_factory=list)
    flent_options = FlentPlotOptions()
    iperf3_files: List[Path] = field(default_factory=list)
    iperf3_options = IPerf3PlotOptions()

    def clear_files(self):
        self.flent_files.clear()
        self.iperf3_files.clear()


def exploration_plots(options: ExplorePlotOptions):
    cols = bool(len(options.flent_files)) + bool(len(options.iperf3_files))
    if cols == 0:
        return
    rows = max(len(options.flent_files), len(options.iperf3_files))
    fig, axes = plt.subplots(rows, cols, figsize=(12, 6))

    if cols == 1 and rows == 1:
        axes = [axes]
    is_onedimensional = cols == 1 or rows == 1

    for idx, file in enumerate(options.flent_files):
        if is_onedimensional:
            ax = axes[idx]
        else:
            ax = axes[idx][0]

        plot_flent_file(fig, ax, file, options.flent_options)

    for idx, file in enumerate(options.iperf3_files):
        if is_onedimensional:
            ax = axes[idx - len(options.flent_files)]
        else:
            ax = axes[idx][1]

        plot_iperf3_file(fig, ax, file, options.iperf3_options)

    fig.legend()
    plt.show()


def plot_flent_file(fig, ax, file: Path, options: FlentPlotOptions):
    with gzip.open(file, "r") as f:
        data = json.load(f)

    x_values = data["x_values"]

    results = data["results"]

    rate = options.enforced_gbit_rate
    lower_bound = 0.5 * rate
    upper_bound = 1.5 * rate
    buf = 0.1 * rate

    start_idx = max(bisect.bisect_left(x_values, options.interval_start) - 1, 0)
    end_idx = min(bisect.bisect_right(x_values, options.interval_end) + 1, len(x_values))

    xs = x_values[start_idx:end_idx + 1]
    ys = results[options.key][start_idx:end_idx + 1]

    ys = list(map(lambda x: None if x is None else x / 1024, ys))

    sampling_rate = (max(xs) - min(xs)) / (len(xs) - 1)

    ax.set_xlim(options.interval_start, options.interval_end)

    ax.set_xlabel("Time after test start in seconds")
    ax.set_ylabel("Rate in Gbit/s")

    ax.hlines(rate, options.interval_start, options.interval_end, colors="green",
              label="Rate to enforce", linestyle="dashed", linewidth=2)
    if options.show_bounds:
        ax.set_ylim(lower_bound - buf, upper_bound + buf)
        ax.hlines([lower_bound, upper_bound], options.interval_start, options.interval_end, colors="black",
                  label="Burst-control bounds", linestyle="dashed", linewidth=2)
    else:
        mx = max(y for y in ys if y is not None)
        mn = min(y for y in ys if y is not None)
        dist = max(mx - rate, rate - mn) * 1.2
        ax.set_ylim(rate - dist, rate + dist)

    if options.show_avg:
        value_ys = [y for y in ys if y is not None]
        avg = sum(value_ys) / len(value_ys)
        ax.hlines(avg, options.interval_start, options.interval_end, colors="red",
                  label="Actually enforced rate", linestyle="dashed", linewidth=2)

    ax.plot(xs, ys, label=f"{options.key} in Gbit/s sampled at {round(sampling_rate * 1000)}ms intervals")


def _prep_iperf3_data(data_file: Path, options: IPerf3PlotOptions):
    with open(data_file, "r") as f:
        data = json.load(f)

    # TODO: plot streams separately if requested

    xs = []
    ys = []

    for i, interval in enumerate(data["intervals"]):
        s = interval["sum"]
        if s["start"] >= options.test_end:
            break
        width = s["end"] - s["start"]
        assert abs(width - options.interval_width) < width * 0.01, f"{width=} doesn't match {options.interval_width=}"
        xs.append(i * options.interval_width)
        bits = s["bytes"] * 8
        if options.remove_headers:
            bits -= s["packets"] * 28 * 8  # subtract udp header size
        ys.append(bits / (1024**3 * options.interval_width))

    # when using step, we need to re-add the last data point
    xs.append(xs[-1] + options.interval_width)
    ys.append(ys[-1])

    return xs, ys


def plot_iperf3_file(fig, ax, file: Path, options: IPerf3PlotOptions):
    xs, ys = _prep_iperf3_data(file, options)

    ax.step(xs, ys, where="post",
            label=f"UDP upload in Gbit/s sampled at {options.interval_width}s intervals")

    if options.send_gbit_rate and any("client" in part for part in file.parts):
        ax.hlines(options.send_gbit_rate, min(xs), max(xs), colors="green",
                  label="Sending rate", linestyle="dashed", linewidth=2)
    if any("server" in part for part in file.parts):
        ax.hlines(options.enforced_gbit_rate, min(xs), max(xs), colors="green",
                  label="Rate to enforce", linestyle="dashed", linewidth=2)
        if options.show_avg:
            value_ys = [y for y in ys if y is not None]
            avg = sum(value_ys) / len(value_ys)
            ax.hlines(avg, min(xs), max(xs), colors="red",
                      label="Actually enforced rate", linestyle="dashed", linewidth=2)

    ax.set_xlabel("Time after test start in seconds")
    ax.set_ylabel("Rate in Gbit/s")


def bursty_plot(save_plots: bool):
    fig, ax = plt.subplots(1, 1, figsize=(6, 6))
    options = IPerf3PlotOptions()

    # data_file = DATA_DIR / "bc-test" / "non-fluent-server.json"
    data_file = DATA_DIR / "bc-test" / "fluent-pqp-server.json"
    xs, ys = _prep_iperf3_data(data_file, options)

    ax.step(xs, ys, where="post", color=COLORS[0], linewidth=2)

    ax.hlines(options.enforced_gbit_rate, min(xs), max(xs), colors="black",
              label="Rate to enforce", linestyle="dashed", linewidth=2)

    ax.set_xlabel("Time in seconds")
    ax.set_ylabel("Rate in Gbit/s")

    ax.set_xlim(0, 2)
    ax.set_ylim(-0.01, 6)

    ax.legend(loc="upper right")

    out_path = PROGRESS_PRESENTATION_DIR / "bursty_traffic.pdf"

    save_or_show(fig, out_path, save_plots)


def progress_plot(save_plots: bool):
    fig, ax = plt.subplots(1, 1, figsize=(12, 6))
    options = IPerf3PlotOptions()

    files = [
        DATA_DIR / "bc-test" / "non-fluent-server.json",
        DATA_DIR / "bc-test" / "fluent-pqp-server.json",
        DATA_DIR / "bc-test" / "bc-pqp-server.json",
    ]
    xy_pairs = [_prep_iperf3_data(data_file, options) for data_file in files]

    labels = [
        "Naive token bucket",
        "PQP",
        "BC-PQP"
    ]

    for color, (xs, ys), label in zip(COLORS, xy_pairs, labels):
        ax.step(xs, ys, where="post", color=color, linewidth=2, label=label)

    ax.hlines(options.enforced_gbit_rate, min(xs), max(xs), colors="black",
              label="Rate to enforce", linestyle="dashed", linewidth=2)

    ax.set_xlabel("Time in seconds")
    ax.set_ylabel("Rate in Gbit/s")

    ax.set_xlim(0, 5)
    ax.set_ylim(-0.01, 5.7)

    ax.legend(loc="upper right")

    out_path = PROGRESS_PRESENTATION_DIR / "versions.pdf"

    save_or_show(fig, out_path, save_plots)


def save_or_show(fig: plt.figure, path: Path, save_plot: bool):
    print(path)
    if save_plot:
        yes = input("Save this? (y/n) ") == "y"
        if yes:
            fig.savefig(path, bbox_inches='tight', transparent=True)
    else:
        plt.show()


if __name__ == "__main__":
    save_plots = input("Press 'S' to save the plots instead of showing them: ").lower().startswith("s")
    bursty_plot(save_plots)
    progress_plot(save_plots)

    if save_plots or input("Press ENTER to continue with \"exploration plots\" "):
        # do not show "exploration plots"
        exit(0)

    options = ExplorePlotOptions()
    options.iperf3_files.append(DATA_DIR / "bc-test" / "non-fluent-client.json")
    options.iperf3_files.append(DATA_DIR / "bc-test" / "non-fluent-server.json")
    options.iperf3_options.send_gbit_rate = 6 * 1000**3 / 1024**3
    options.iperf3_options.show_avg = True
    exploration_plots(options)

    options.clear_files()
    options.iperf3_files.append(DATA_DIR / "bc-test" / "fluent-pqp-client.json")
    options.iperf3_files.append(DATA_DIR / "bc-test" / "fluent-pqp-server.json")
    exploration_plots(options)

    options.clear_files()
    options.iperf3_files.append(DATA_DIR / "bc-test" / "bc-pqp-client.json")
    options.iperf3_files.append(DATA_DIR / "bc-test" / "bc-pqp-server.json")
    exploration_plots(options)
