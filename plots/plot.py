import bisect
import gzip
import json

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import matplotlib.pyplot as plt
import seaborn as sns
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
FINAL_PRESENTATION_DIR = EVAL_DIR / "final-presentation" / "figures"

COLORS = ["#D81B60", "#1E88E5", "#FFC107", "#004D40"]

set_fontsize(16)


@dataclass
class FlentPlotOptions:
    key: str = "TCP upload"
    interval_start: float = 0
    interval_end: float = 20
    enforced_gbit_rate: float = 1.0
    show_bounds: bool = True
    show_avg: bool = True


@dataclass
class IPerf3PlotOptions:
    test_end: float = 5
    interval_start: Optional[float] = None
    interval_end: Optional[float] = None
    remove_headers: bool = False
    plot_sum: bool = False
    stack_streams: bool = True
    send_gbit_rate: Optional[float] = None
    enforced_gbit_rate: float = 1.0
    show_enforced_rate: bool = True
    show_tail: bool = False


@dataclass
class ExplorePlotOptions:
    flent_files: List[Path] = field(default_factory=list)
    flent_options = FlentPlotOptions()
    iperf3_files: List[Path] = field(default_factory=list)
    iperf3_options = IPerf3PlotOptions()
    legend: bool = True

    def clear_files(self):
        self.flent_files.clear()
        self.iperf3_files.clear()


def exploration_plots(options: ExplorePlotOptions):
    print("PLOT:")
    if options.flent_files:
        print("  " + ", ".join(str(f.relative_to(DATA_DIR)) for f in options.flent_files))
    if options.iperf3_files:
        print("  " + ", ".join(str(f.relative_to(DATA_DIR)) for f in options.iperf3_files))
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

    if options.legend:
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
        raw_text = f.read().lstrip()

    is_client = None

    total_data_by_port = defaultdict(list)

    min_test_start_sec = None

    decoder = json.JSONDecoder()
    while raw_text:
        partial_data, index = decoder.raw_decode(raw_text)
        raw_text = raw_text[index:].lstrip()
        if "error" in partial_data:
            err = partial_data["error"]
            if err == "interrupt - the server has terminated by signal Interrupt(2)":
                continue
            raise RuntimeError(f"Found unexpected error '{err}' in JSON")

        this_is_client = "connecting_to" in partial_data["start"]
        if is_client is None:
            is_client = this_is_client
        else:
            assert is_client == this_is_client, "Cannot mix client and server files"

        target_rate = partial_data["start"]["target_bitrate"] / 1024**3
        if options.send_gbit_rate is not None:
            assert target_rate != 0 and abs((target_rate - options.send_gbit_rate) / target_rate) <= 0.01

        test_start_sec = partial_data["start"]["timestamp"]["timesecs"]
        if min_test_start_sec is None or test_start_sec < min_test_start_sec:
            min_test_start_sec = test_start_sec

        socket_ports = {}
        for socket_data in partial_data["start"]["connected"]:
            socket_number = socket_data["socket"]
            port_key = "local_port" if is_client else "remote_port"
            port = socket_data[port_key]
            socket_ports[socket_number] = port

        is_first = {socket: True for socket in socket_ports.keys()}
        is_first_sum = True

        data_by_port = {"sum": ([], [])}

        def val_func(byte_val, start, end):
            return (byte_val * 8 / 1024**3) / (end - start)

        for i, interval_data in enumerate(partial_data["intervals"]):
            for stream_data in interval_data["streams"]:
                socket = stream_data["socket"]
                port = socket_ports[socket]
                if port not in data_by_port:
                    data_by_port[port] = ([], [])
                xs, ys = data_by_port[port]
                val = val_func(stream_data["bytes"], stream_data["start"], stream_data["end"])
                if is_first[socket]:
                    xs.append(stream_data["start"])
                    ys.append(val)
                    is_first[socket] = False
                xs.append(stream_data["end"])
                ys.append(val)

            sum_data = interval_data["sum"]
            xs, ys = data_by_port["sum"]
            val = val_func(sum_data["bytes"], sum_data["start"], sum_data["end"])

            if is_first_sum:
                xs.append(sum_data["start"])
                ys.append(val)
                is_first_sum = False
            xs.append(sum_data["end"])
            ys.append(val)

        if options.stack_streams:
            ports_sorted = list(sorted(socket_ports.values()))
            for i, (prev_port, port) in enumerate(zip(ports_sorted[:-1], ports_sorted[1:])):
                prev_xs, prev_ys = data_by_port[prev_port]
                xs, ys = data_by_port[port]

                stacked_xs = []
                stacked_ys = []

                i = 0
                j = 0
                while i < len(prev_xs) and j < len(xs):
                    stacked_ys.append(prev_ys[i] + ys[j])
                    if prev_xs[i] == xs[j]:
                        stacked_xs.append(xs[j])
                        i += 1
                        j += 1
                    elif prev_xs[i] < xs[j]:
                        stacked_xs.append(prev_xs[i])
                        i += 1
                    else:
                        stacked_xs.append(xs[j])
                        j += 1
                if options.show_tail:
                    while i < len(prev_xs):
                        stacked_xs.append(prev_xs[i])
                        stacked_ys.append(prev_ys[i])
                        i += 1
                    while j < len(xs):
                        stacked_xs.append(xs[j])
                        stacked_ys.append(ys[j])
                        j += 1

                assert len(stacked_xs) == len(stacked_ys), f"{len(stacked_xs)=} != {len(stacked_ys)=}"

                data_by_port[port] = stacked_xs, stacked_ys

        for key, (xs, ys) in data_by_port.items():
            total_data_by_port[key].append((test_start_sec, xs, ys))

    return min_test_start_sec, is_client, total_data_by_port


def plot_iperf3_file(fig, ax, file: Path, options: IPerf3PlotOptions):
    min_test_start, is_client, data_by_port = _prep_iperf3_data(file, options)

    colors = sns.color_palette()
    color_idx = 0

    color_by_port = {}

    min_x = None
    max_x = None

    for key, entries in data_by_port.items():
        if key == "sum" and not options.plot_sum:
            continue
        for test_start, xs, ys in entries:
            name = f"Port {key}" if key != "sum" else "Sum"

            if name not in color_by_port:
                color = colors[color_idx % len(colors)]
                color_idx += 1
                color_by_port[name] = color
            color = color_by_port[name]

            xs = list(map(lambda x: x + test_start - min_test_start, xs))
            if min_x is None or xs[0] < min_x:
                min_x = xs[0]
            if max_x is None or xs[-1] > max_x:
                max_x = xs[-1]

            ax.step(xs, ys, where="pre", label=name, color=color)

            if not is_client and options.show_avg:
                avg = 0
                for prev_x, x, y in zip(xs[:-1], xs[1:], ys[1:]):
                    avg += y * (x - prev_x)
                avg /= xs[-1] - xs[0]
                ax.hlines(avg, min(xs), max(xs), colors=color,
                          label=f"Actually enforced rate ({name})", linestyle="dashed", linewidth=2)

    if options.send_gbit_rate and is_client:
        ax.hlines(options.send_gbit_rate, min_x, max_x, colors="green",
                  label="Sending rate", linestyle="dashed", linewidth=2)
    if options.show_enforced_rate and not is_client:
        ax.hlines(options.enforced_gbit_rate, min(xs), max(xs), colors="green",
                  label="Rate to enforce", linestyle="dashed", linewidth=2)

    ax.set_xlim(options.interval_start, options.interval_end)
    ax.set_ylim(0, None)

    ax.set_xlabel("Time after test start in seconds")
    ax.set_ylabel("Rate in Gbit/s")


def plot_bursty_iperf3(file: Path, debug=False, bc_threshhold=True, rate=True, save=False, name="burst_iperf3"):
    def val_func(byte_val, start, end):
        return (byte_val * 8 / 1024**3) / (end - start)

    with open(file, "r") as f:
        raw_text = f.read().lstrip()

    data = []

    baseline_idx = None

    decoder = json.JSONDecoder()
    while raw_text:
        partial_data, index = decoder.raw_decode(raw_text)
        raw_text = raw_text[index:].lstrip()
        if "error" in partial_data:
            err = partial_data["error"]
            if err == "interrupt - the server has terminated by signal Interrupt(2)":
                continue
            raise RuntimeError(f"Found unexpected error '{err}' in JSON")

        test_start_sec = partial_data["start"]["timestamp"]["timesecs"]

        xs = []
        ys = []

        is_first = True
        for i, interval_data in enumerate(partial_data["intervals"]):
            assert len(interval_data["streams"]) == 1
            stream_data = interval_data["streams"][0]
            val = val_func(stream_data["bytes"], stream_data["start"], stream_data["end"])
            if is_first:
                xs.append(stream_data["start"])
                ys.append(-1)
                is_first = False
            xs.append(stream_data["end"])
            ys.append(val)

        idx = len(data)
        data.append((test_start_sec, xs, ys))
        if baseline_idx is None or data[baseline_idx][0] > test_start_sec:
            baseline_idx = idx

    base_start, base_xs, base_ys = data[baseline_idx]

    non_baseline_idx = sorted(
        (i for i in range(len(data)) if i != baseline_idx),
        key=lambda idx: data[idx][0]
    )

    accumulated_xs = []
    accumulated_ys = []

    i = 1
    for non_baseline_i in non_baseline_idx:
        start, xs, ys = data[non_baseline_i]

        while i < len(base_ys) and abs(base_ys[i] - base_ys[max(i - 1, 1)]) < 0.02:
            accumulated_xs.append(base_xs[i])
            accumulated_ys.append(base_ys[i])
            i += 1

        for j, y in enumerate(ys):
            if j == 0:
                continue
            accumulated_xs.append(base_xs[i])
            accumulated_ys.append(base_ys[i] + y)
            i += 1

        for _ in range(3):
            # small buffer
            accumulated_xs.append(base_xs[i])
            accumulated_ys.append(base_ys[i])
            i += 1

    while i < len(base_ys):
        accumulated_xs.append(base_xs[i])
        accumulated_ys.append(base_ys[i])
        i += 1

    fig, ax = plt.subplots(1, 1, figsize=(12, 6))
    mode = "post"
    if debug:
        ax.step(base_xs[1:-1], base_ys[1:-1], where=mode)
    ax.step(accumulated_xs[:-1], accumulated_ys[:-1], where=mode,
            label="Measured traffic")

    if bc_threshhold:
        ax.hlines(1.5, min(accumulated_xs), max(accumulated_xs), colors="red",
                  label="Upper burst threshold", linestyle="dashed", linewidth=2)

    if rate:
        ax.hlines(1, min(accumulated_xs), max(accumulated_xs), colors="green",
                  label="Rate limit", linestyle="dashed", linewidth=2)

    # ax.set_xlim(options.interval_start, options.interval_end)
    ax.set_ylim(0, None)

    ax.set_xlabel("Time after test start in seconds")
    ax.set_ylabel("Rate in Gbit/s")

    ax.legend(loc="lower right")

    out_path = FINAL_PRESENTATION_DIR / f"{name}.pdf"
    save_or_show(fig, out_path, save)


def plot_flow_server_file(file: Path, show_tx=True, save=False, name="flow_server"):
    with open(file, "r") as f:
        obj = json.load(f)

    assert isinstance(obj, list) and len(obj) == 1
    obj = obj[0]
    obj = obj["data"]["out"]["throughput"]

    rx_obj = obj["RX"]
    tx_obj = obj["TX"]

    rx_times = rx_obj["Time_vals"]
    tx_times = tx_obj["Time_vals"]

    def val_func(mbit_val):
        return mbit_val / 1024

    rx_vals = list(map(val_func, rx_obj["Mbit_vals"]))
    tx_vals = list(map(val_func, tx_obj["Mbit_vals"]))

    fig, ax = plt.subplots(1, 1, figsize=(12, 6))

    ax.plot(rx_times, rx_vals, label="Traffic received")
    if show_tx:
        ax.plot(tx_times, tx_vals, label="Traffic sent")

    ax.set_xlabel("Time after test start in seconds")
    ax.set_ylabel("Rate in Gbit/s")
    ax.legend()

    out_path = FINAL_PRESENTATION_DIR / f"{name}.pdf"
    save_or_show(fig, out_path, save)


def plot_scale_server_file(file: Path, show_tx=True, show_physical_cores=20, save=False, name="scale_server", min_y_zoom: Optional[float] = None):
    with open(file, "r") as f:
        obj = json.load(f)

    assert isinstance(obj, list)  # and len(obj) == 1

    data64 = {}
    data_mtu = {}

    def val_func(mbit_val):
        return mbit_val / 1024

    for o in obj:
        queue_count = o["config"]["txqs"]
        pkt_size = o["config"]["pkt-size"]
        o_data = o["data"]["out"]["throughput"]
        rx_val = val_func(o_data["RX"]["Mbit"])
        tx_val = val_func(o_data["TX"]["Mbit"])
        if pkt_size == 64:
            data64[queue_count] = (rx_val, tx_val)
        elif pkt_size == 1514:
            data_mtu[queue_count] = (rx_val, tx_val)
        else:
            assert False, f"{pkt_size=} is neither 64 nor 1514"

    fig64, ax64 = plt.subplots(1, 1, figsize=(8, 6))
    fig_mtu, ax_mtu = plt.subplots(1, 1, figsize=(8, 6))

    counts = []
    rx_vals = []
    tx_vals = []
    for count, (rx, tx) in sorted(data64.items()):
        counts.append(count)
        rx_vals.append(rx)
        tx_vals.append(tx)
    ax64.plot(counts, rx_vals, label="Traffic received")
    if show_tx:
        ax64.plot(counts, tx_vals, label="Traffic sent")
    if min_y_zoom is not None:
        y_min, y_max = ax64.get_ylim()
        if y_max - y_min < min_y_zoom:
            y_middle = (y_min + y_max) / 2
            half = min_y_zoom / 2
            ax64.set_ylim(y_middle - half, y_middle + half)
    ax64.set_xlabel("Number of CPU cores")
    ax64.set_ylabel("Average throughput in Gbit/s")
    if isinstance(show_physical_cores, int) and show_physical_cores > 0:
        y_min, y_max = ax64.get_ylim()
        ax64.vlines(show_physical_cores, y_min, y_max, color="red", linewidth=2, label="\#Physical cores")
    ax64.legend()

    counts = []
    rx_vals = []
    tx_vals = []
    for count, (rx, tx) in sorted(data_mtu.items()):
        counts.append(count)
        rx_vals.append(rx)
        tx_vals.append(tx)
    ax_mtu.plot(counts, rx_vals, label="Traffic received")
    if show_tx:
        ax_mtu.plot(counts, tx_vals, label="Traffic sent")
    if min_y_zoom is not None:
        y_min, y_max = ax_mtu.get_ylim()
        if y_max - y_min < min_y_zoom:
            y_middle = (y_min + y_max) / 2
            half = min_y_zoom / 2
            ax_mtu.set_ylim(y_middle - half, y_middle + half)
    ax_mtu.set_xlabel("Number of CPU cores")
    ax_mtu.set_ylabel("Average throughput in Gbit/s")
    if isinstance(show_physical_cores, int) and show_physical_cores > 0:
        y_min, y_max = ax_mtu.get_ylim()
        ax_mtu.vlines(show_physical_cores, y_min, y_max, color="red", linewidth=2, label="\#Physical cores")
    ax_mtu.legend()

    out_path_64 = FINAL_PRESENTATION_DIR / f"{name}_64.pdf"
    save_or_show(fig64, out_path_64, save)
    out_path_mtu = FINAL_PRESENTATION_DIR / f"{name}_mtu.pdf"
    save_or_show(fig_mtu, out_path_mtu, save)


def plot_enforcement_server_file(file: Path, show_tx=True, show_linear=False, save=False, name="scale_server"):
    with open(file, "r") as f:
        obj = json.load(f)

    assert isinstance(obj, list)  # and len(obj) == 1

    data = {}

    def val_func(mbit_val):
        return mbit_val / 1024

    for o in obj:
        maxrate = o["config"]["maxrate"] / 1000
        o_data = o["data"]["out"]["throughput"]
        rx_val = val_func(o_data["RX"]["Mbit"])
        tx_val = val_func(o_data["TX"]["Mbit"])
        data[maxrate] = (rx_val, tx_val)

    fig, ax = plt.subplots(1, 1, figsize=(12, 6))

    counts = []
    rx_vals = []
    tx_vals = []
    for count, (rx, tx) in sorted(data.items()):
        counts.append(count)
        rx_vals.append(rx)
        tx_vals.append(tx)
    ax.plot(counts, rx_vals, label="Traffic received")
    if show_tx:
        ax.plot(counts, tx_vals, label="Traffic sent")
    if show_linear:
        x = [min(counts), max(counts)]
        ax.plot(x, x, label="Expectation", color="red", linestyle="dashed", linewidth=2)

    ax.set_xlabel("Configured rate to enforce")
    ax.set_ylabel("Average enforced rate in Gbit/s")
    ax.legend()

    out_path = FINAL_PRESENTATION_DIR / f"{name}.pdf"
    save_or_show(fig, out_path, save)


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
        plt.close()
    else:
        plt.show()


if __name__ == "__main__":

    save_plots = input("Press 'S' to save the plots instead of showing them: ").lower().startswith("s")
    plot_enforcement_server_file(DATA_DIR / "server-v2" / "rxq_8_flows_8.json", name="nonsharded_enforcement_8", show_linear=True, save=save_plots)
    plot_enforcement_server_file(DATA_DIR / "server-v2" / "rxq_8_flows_16.json", name="nonsharded_enforcement_16", show_linear=True, save=save_plots)
    plot_enforcement_server_file(DATA_DIR / "server-v2" / "rxq_8_flows_32.json", name="nonsharded_enforcement_32", show_linear=True, save=save_plots)
    plot_bursty_iperf3(DATA_DIR / "tcp" / "burst-server.json", name="nonsharded_tcp_burst", save=save_plots)
    plot_bursty_iperf3(DATA_DIR / "tcp" / "reno-burst-server.json", name="nonsharded_reno_tcp_burst", save=save_plots)
    # plot_flow_server_file(DATA_DIR / "server-v2" / "flow-data.json", name="nonshared_flow_exp", save=save_plots)
    plot_scale_server_file(DATA_DIR / "server-v2" / "scale-data.json", name="nonshared_scale_exp", save=save_plots)
    plot_scale_server_file(DATA_DIR / "server-v2" / "baseline_scaling.json", name="baseline_scale_exp", save=save_plots)
    plot_bursty_iperf3(DATA_DIR / "burst" / "server.json", name="nonsharded_udp_burst", save=save_plots)

    if input("Press ENTER to continue with \"exploration plots\" "):
        # do not show "exploration plots"
        exit(0)

    options = ExplorePlotOptions()
    options.iperf3_options.show_avg = False
    options.iperf3_options.show_enforced_rate = False
    options.legend = False

    options.clear_files()
    options.iperf3_files.append(DATA_DIR / "burst" / "client.json")
    options.iperf3_files.append(DATA_DIR / "burst" / "server.json")
    exploration_plots(options)

    options.clear_files()
    options.iperf3_files.append(DATA_DIR / "tcp" / "client.json")
    options.iperf3_files.append(DATA_DIR / "tcp" / "server.json")
    exploration_plots(options)

    options.clear_files()
    options.iperf3_files.append(DATA_DIR / "tcp" / "burst-client.json")
    options.iperf3_files.append(DATA_DIR / "tcp" / "burst-server.json")
    exploration_plots(options)

    options.clear_files()
    options.iperf3_files.append(DATA_DIR / "tcp" / "reno-burst-client.json")
    options.iperf3_files.append(DATA_DIR / "tcp" / "reno-burst-server.json")
    exploration_plots(options)
