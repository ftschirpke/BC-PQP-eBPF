#!/usr/bin/env bash

help() {

cat <<EOF
Usage:  $0 [ -h ]
        $0 [ -d ] command

    This script functions as a wrapper around the net.sh script.
    It groups multiple helpful commands and tries to execute them in
    separate tmux panes.

    -h|--help                   Show this help
    -d|--dry-run                Only list the commands that would have been executed

    Commands:
        help                    Show this help
        debug_network           Send pings through the network and dump packets
                                to see whether network setup works as expected
        debug_network_full      Send pings through the network and dumps even more packets
                                than debug_network
        simple_test             Runs a simple iperf3 network test
        advanced_test           Runs the default flent network test
        all_tests               Runs a selected sequence of flent network tests
EOF

}

commands=()

dir=$(realpath $(dirname "$0"))

dry_run=false
command=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            help
            exit 0
            ;;
        -d|--dry-run)
            dry_run=true
            shift
            ;;
        -*|--*)
            echo "Unknown option $1"
            help
            exit 1
            ;;
        *)
            [ -z "$command" ] || { echo "Found option '$1' while already specified command: $command"; exit 1; }
            command="$1"
            shift
            ;;
    esac
done

case $command in
    debug_network)
        commands=(
            "$dir/net.sh debug ping"
            "$dir/net.sh debug dump icmp"
        )
        ;;
    debug_network_full)
        commands=(
            "$dir/net.sh debug ping"
            "$dir/net.sh debug dump --decode --client"
            "$dir/net.sh debug dump --decode --client --namespace"
            "$dir/net.sh debug dump --decode --server"
        )
        ;;
    simple_test)
        commands=(
            "$dir/net.sh test simple server"
            "$dir/net.sh test simple client"
        )
        ;;
    advanced_test)
        commands=(
            "$dir/net.sh test advanced server"
            "$dir/net.sh test advanced client"
        )
        ;;
    burst_test)
        mkdir -p tests-$(git rev-parse HEAD)
        cd tests-$(git rev-parse HEAD)
        # NOTE: do not rely on this, rather use it as help on what you could do to (manually) run a bursty test
        commands=(
            "$dir/net.sh test simple server -o burst-server.json -x 5201"
            "$dir/net.sh test simple server -o burst-server.json -x 5202"
            "$dir/net.sh test simple client -o burst-client.json -t 20 -x 5201 -b 400M -c 12345"
"$(cat<<EOF
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345 &&
sleep 0.5 &&
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345 &&
sleep 0.5 &&
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345 &&
sleep 0.5 &&
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345 &&
sleep 0.5 &&
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345 &&
sleep 0.5 &&
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345 &&
sleep 0.5 &&
$dir/net.sh test simple client -o burst-client.json -t 2 -x 5202 -c 13345
EOF
)"
        )
        echo Put a simple description of the state of the project here >> README
        "${EDITOR:-vi}" README
        ;;
    *)
        echo "Unknown command $1"
        help
        exit 1
        ;;
esac

if [[ -z "$TMUX" ]]; then
    echo "Not running inside tmux."
fi

# TODO: consider adding non-tmux solution
if [[ -z "$TMUX" ]] || [[ "$dry_run" == true ]]; then
    echo "Would have (simultaneously) run:"
    for cmd in "${commands[@]}"; do
        echo "> $cmd"
    done
    exit 0
fi

for i in "${!commands[@]}"; do
    tmux split-window -v
    tmux select-layout tiled >/dev/null
    tmux send-keys "${commands[i]}" C-m
done
