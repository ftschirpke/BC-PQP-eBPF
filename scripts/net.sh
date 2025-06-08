#!/usr/bin/env bash

CLIENT_NAMESPACE="ns1"
SERVER_NAMESPACE="ns2"
CLIENT_IF="veth1_ns"
SERVER_IF="veth2_ns"
CLIENT_IP=192.168.101.10
SERVER_IP=192.168.102.10
CLIENT_VETH_IF="veth1_host"
SERVER_VETH_IF="veth2_host"
CLIENT_VETH_IP=192.168.101.20
SERVER_VETH_IP=192.168.102.20
CLIENT_BRIDGE_IF="br1"
SERVER_BRIDGE_IF="br2"
CLIENT_BRIDGE_IP=192.168.101.30
SERVER_BRIDGE_IP=192.168.102.30
CLIENT_VM_IF="eth0"
SERVER_VM_IF="eth1"
CLIENT_VM_IP=192.168.101.100
SERVER_VM_IP=192.168.102.100


help() {

cat <<EOF
Usage:  $0 [ -h ]
        $0 { help | debug | test } [ subcommand options ]

    This script functions as a collection and wrapper of commands
    for debugging and testing our network setup and XDP program.
    The benefit is that you have all commands in one place, the 
    IP addresses etc. already configured, as well as sensible default
    paramenters.

    -h|--help           Show this help

    Subcommands:
        help            Show this help
        debug           Collection of commands to debug the network
                        and XDP program. Here you may find packet-level
                        commands like ping, tcpdump, hping3, ...
        test            Collection of tests using network testing tools
                        such as iperf3 and flent
EOF

}

debug__help() {

cat <<EOF
Usage:  $0 debug [ -h ]
        $0 debug { help | dump | ping } [ subcommand options ]

    Collection of (packet-level) commands helping in debugging.

    -h|--help           Show this help

    Subcommands:
        help            Show this help
        dump            Dump packets using tcpdump
        ping            Ping different network interfaces
EOF

}

debug__dump__help() {

cat <<EOF
Usage:  $0 debug dump [ -h ] [ -d ] [ -c | -s ] [ -n | -v | -b ] { filter }

    Dump packets 

    -h|--help           Show this help
    -d|--decode         Decode packet protocol, flags, etc.

    -c|--client         (Default) Dump packets at client-side
    -s|--server         Dump packets at server-side

    The following options allow you to select the interface to listen
    at and are therefore only possible on the host:
    (in the VM, this is ignored)

    -b|--bridge         (Default) Dump packets at network interface of bridge
                        connecting host to VM at client or server side
    -v|--veth           Dump packets at network interface of virtual
                        ethernet connection to network namespace
    -n|--namespace      Dump packets at network interface
                        inside client's or server's network namespace

    filter              Expression filtering of which packets to dump
                        Example: icmp to show only packets of ping for example
                        Default: no filter
EOF

}

debug__dump() {
    is_vm=$(expr "$(uname -n)" == "ebpf")
    decode=""
    side=""
    type=""
    positional_args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                debug__dump__help
                return 0
                ;;
            -d|--decode)
                decode="-v"
                shift
                ;;
            -c|--client)
                [ -z "$side" ] || { echo "Found option '$1' while already specified $side side."; return 1; }
                side="client"
                shift
                ;;
            -s|--server)
                [ -z "$side" ] || { echo "Found option '$1' while already specified $side side."; return 1; }
                side="server"
                shift
                ;;
            -n|--namespace)
                [ -z "$type" ] || { echo "Found option '$1' while already specified $type as the type."; return 1; }
                type="namespace"
                shift
                ;;
            -v|--veth)
                [ -z "$type" ] || { echo "Found option '$1' while already specified $type as the type."; return 1; }
                type="veth"
                shift
                ;;
            -b|--bridge)
                [ -z "$type" ] || { echo "Found option '$1' while already specified $type as the type."; return 1; }
                type="bridge"
                shift
                ;;
            -*|--*)
                echo "Unknown option $1"
                debug__dump__help
                return 1
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    ip=""
    if [[ "$side" == "server" ]]; then
        if [[ "$is_vm" == true ]]; then
            ip="$SERVER_VM_IF"
        elif [[ "$type" == "veth" ]]; then
            ip="$SERVER_VETH_IF"
        elif [[ "$type" == "namespace" ]]; then
            cmd="sudo ip netns exec $SERVER_NAMESPACE tcpdump -i $SERVER_IF"
        else
            ip="$SERVER_BRIDGE_IF"
        fi
    else
        if [[ "$is_vm" == true ]]; then
            ip="$CLIENT_VM_IF"
        elif [[ "$type" == "veth" ]]; then
            ip="$CLIENT_VETH_IF"
        elif [[ "$type" == "namespace" ]]; then
            cmd="sudo ip netns exec $CLIENT_NAMESPACE tcpdump -i $CLIENT_IF"
        else
            ip="$CLIENT_BRIDGE_IF"
        fi
    fi

    if [[ "$cmd" == "" ]]; then
        if [[ "$is_vm" == true ]]; then
            cmd="tcpdump -i $ip"
        else
            cmd="sudo tcpdump -i $ip"
        fi
    fi

    cmd+=" ${positional_args[@]}"

    echo "Executing: $cmd"
    echo "tcpdump may take a few seconds to start up, please wait..."
    echo

    bash -c "$cmd"
    return 0
}

debug__ping__help() {

cat <<EOF
Usage:  $0 debug ping [ -h ] [ -r ] [ -m ] [ -t target ]
                      [ -i interval | -f ] [ --icmp | --tcp | --rawip | --udp ]

    Ping network interfaces 

    -h|--help           Show this help

    -r|--reverse        Reverse ping direction from the default
                        client->server to server->client
    -m|--master         Ping from master network namespace, instead of
                        client's or server's network namespace
                        (has no effect from inside the VM)
    -t|--target <val>   The target of the ping:
                          * ns - (Default) the target side's network namepace
                          * veth - the target side's host side of the veth
                          * bridge - the target side's bridge to the VM
                          * vm-in - VM ingress
                          * vm-out - VM egress

    -i|--interval <val> The interval between packets sent.
                        '-i 1' for 1 second or '-i u200' for 200 microseconds
    -f|--flood          Send as much packets as possible

    --icmp              (Default) Send ICMP packets
    --tcp               Send TCP packets
    --rawip             Send raw IP packets
    --udp               Send UDP packets
EOF

}

debug__ping() {
    is_vm=$([[ "$(uname -n)" == "ebpf" ]] && echo true || echo false)
    reverse=false
    master=false
    target=""
    interval=""
    type=""
    positional_args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                debug__ping__help
                return 0
                ;;
            -r|--reverse)
                reverse=true
                shift
                ;;
            -m|--master)
                master=true
                shift
                ;;
            -t|--target)
                [ -z "$target" ] || { echo "Found option '$1' while already specified $target as the target."; return 1; }
                shift
                target="$1"
                shift
                ;;
            -i|--interval)
                [ -z "$interval" ] || { echo "Found option '$1' while already specified $interval as the interval."; return 1; }
                interval="$1 $2"
                shift
                shift
                ;;
            -f|--flood)
                [ -z "$interval" ] || { echo "Found option '$1' while already specified $interval as the interval."; return 1; }
                interval="--flood"
                shift
                ;;
            --icmp|--tcp|--rawip|--udp)
                [ -z "$type" ] || { echo "Found option '$1' while already specified $type as the type."; return 1; }
                type="$1"
                shift
                ;;
            *)
                echo "Unknown option $1"
                debug__ping__help
                return 1
                ;;
        esac
    done

    base_cmd="sudo hping3"
    if [[ "$is_vm" == false ]] && [[ "$master" == false ]]; then
        if [[ "$reverse" == true ]]; then
            base_cmd="sudo ip netns exec $SERVER_NAMESPACE hping3"
        else
            base_cmd="sudo ip netns exec $CLIENT_NAMESPACE hping3"
        fi
    fi

    if [[ "$is_vm" == true ]]; then
        base_cmd="hping3"
    fi

    if [[ "$target" == "" ]]; then
        target="ns"
    fi

    ip=""
    if [[ "$reverse" == true ]]; then
        if [[ "$target" == "ns" ]]; then
            ip="$CLIENT_IP"
        elif [[ "$target" == "veth" ]]; then
            ip="$CLIENT_VETH_IP"
        elif [[ "$target" == "bridge" ]]; then
            ip="$CLIENT_BRIDGE_IP"
        elif [[ "$target" == "vm-out" ]]; then
            ip="$CLIENT_VM_IP"
        elif [[ "$target" == "vm-in" ]]; then
            ip="$SERVER_VM_IP"
        fi
    else
        if [[ "$target" == "ns" ]]; then
            ip="$SERVER_IP"
        elif [[ "$target" == "veth" ]]; then
            ip="$SERVER_VETH_IP"
        elif [[ "$target" == "bridge" ]]; then
            ip="$SERVER_BRIDGE_IP"
        elif [[ "$target" == "vm-out" ]]; then
            ip="$SERVER_VM_IP"
        elif [[ "$target" == "vm-in" ]]; then
            ip="$CLIENT_VM_IP"
        fi
    fi

    if [[ "$type" == "" ]]; then
        type="--icmp"
    fi
    if [[ "$type" == "--tcp" ]]; then
        type=""
    fi

    cmd="$base_cmd $ip $interval $type"

    echo "Executing: $cmd"
    echo

    bash -c "$cmd"
    return 0
}

debug() {
    local cmdname=$1
    if type "debug__$cmdname" >/dev/null 2>&1; then
        shift
        "debug__$cmdname" "$@"
        exit $?
    fi

    # no subcommand was called
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                debug__help
                return 0
                ;;
            -*|--*)
                echo "Unknown option $1"
                debug__help
                return 1
                ;;
            *)
                echo "Unknown subcommand $1"
                debug__help
                return 1
                ;;
        esac
    done

    debug__help
    return 1
}

test__help() {

cat <<EOF
Usage:  $0 test [ -h ]
        $0 test { help | server | simple | advanced } [ subcommand options ]

    Collection of network tests.

    -h|--help           Show this help

    Subcommands:
        help            Show this help
        simple          Simple network testing using iperf3
        advanced        Advanced network testing using flent
EOF

}

test__simple__server__help() {

cat <<EOF
Usage:  $0 test simple server [ -h ] [ -r ]

    Start up an iperf3 server for the use with iperf3 clients.

    -h|--help           Show this help
    -r|--reverse        Reverse roles i.e. use client as server
                        and thus start the server in namespace $CLIENT_NAMESPACE
EOF

}

test__simple__server() {

    reverse=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__simple__server__help
                return 0
                ;;
            -r|--reverse)
                reverse=true
                shift
                ;;
            *)
                echo "Unknown option $1"
                test__simple__server__help
                return 1
                ;;
        esac
    done

    if [[ "$reverse" == true ]]; then
        namespace="$CLIENT_NAMESPACE"
    else
        namespace="$SERVER_NAMESPACE"
    fi

    cmd="sudo ip netns exec $namespace iperf3 -s"

    echo "Executing: $cmd"
    echo

    bash -c "$cmd"
    return 0
}

TEST_SIMPLE_DEFAULT_BITRATE="0"
TEST_SIMPLE_DEFAULT_TIME="10"
TEST_SIMPLE_DEFAULT_STREAMS="1"
TEST_SIMPLE_DEFAULT_PACKET_SIZE="1448"

test__simple__client__help() {

cat <<EOF
Usage:  $0 test simple client [ -h ] [ -r ] [ -b bitrate ] [ -t seconds ]
                      [ -P streams ] [ -o ] [ --udp | --tcp ] [ -s size ]

    Start up an iperf3 client.

    -h|--help           Show this help
    -r|--reverse        Reverse roles i.e. use server as client
                        and thus start the client in namespace $SERVER_NAMESPACE
    -b|--bitrate <val>  Target birate in bits/s (default: $TEST_SIMPLE_DEFAULT_BITRATE i.e. unlimited)
    -t|--time <val>     Time to transmit in seconds (default: $TEST_SIMPLE_DEFAULT_TIME)
    -p|--parallel <val> Number of parallel client streams (default: $TEST_SIMPLE_DEFAULT_STREAMS)
    -o|--output         Also print server output

    --udp               (Default) Send UDP packets
    --tcp               Send TCP packets

    -s|--size <val>     Size of packets to send in bytes (default: $TEST_SIMPLE_DEFAULT_PACKET_SIZE)
EOF

}

test__simple__client() {
    reverse=false
    rate=""
    time=""
    streams=""
    get_server_output=false
    type=""
    size=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__simple__client__help
                return 0
                ;;
            -r|--reverse)
                reverse=true
                shift
                ;;
            -b|--bitrate)
                [ -z "$rate" ] || { echo "Found option '$1' while already specified $rate as the rate."; return 1; }
                shift
                rate="$1"
                shift
                ;;
            -t|--time)
                [ -z "$time" ] || { echo "Found option '$1' while already specified $time as the time."; return 1; }
                shift
                time="$1"
                shift
                ;;
            -p|--parallel)
                [ -z "$streams" ] || { echo "Found option '$1' while already specified $streams as the streams."; return 1; }
                shift
                streams="$1"
                shift
                ;;
            -o|--output)
                get_server_output=true
                shift
                ;;
            --tcp|--udp)
                [ -z "$type" ] || { echo "Found option '$1' while already specified $type as the type."; return 1; }
                type="$1"
                shift
                ;;
            -s|--size)
                [ -z "$size" ] || { echo "Found option '$1' while already specified $size as the size."; return 1; }
                shift
                size="$1"
                shift
                ;;
            *)
                echo "Unknown option $1"
                test__simple__client__help
                return 1
                ;;
        esac
    done

    if [[ "$reverse" == true ]]; then
        namespace="$SERVER_NAMESPACE"
        target="$CLIENT_IP"
    else
        namespace="$CLIENT_NAMESPACE"
        target="$SERVER_IP"
    fi

    if [[ "$rate" == "" ]]; then
        rate="$TEST_SIMPLE_DEFAULT_BITRATE"
    fi

    if [[ "$time" == "" ]]; then
        time="$TEST_SIMPLE_DEFAULT_TIME"
    fi

    if [[ "$streams" == "" ]]; then
        streams="$TEST_SIMPLE_DEFAULT_STREAMS"
    fi
    
    if [[ "$get_server_output" == true ]]; then
        get_server_output="--get-server-output"
    else
        get_server_output=""
    fi

    if [[ "$type" == "" ]]; then
        type="--udp"
    fi
    if [[ "$type" == "--tcp" ]]; then
        type=""
    fi

    if [[ "$size" == "" ]]; then
        size="$TEST_SIMPLE_DEFAULT_PACKET_SIZE"
    fi

    base_cmd="sudo ip netns exec $namespace iperf3 -c $target"

    cmd="$base_cmd -b $rate -t $time -P $streams -l $size $type $get_server_output"

    echo "Executing: $cmd"
    echo

    bash -c "$cmd"
    return 0

}

test__advanced__server__help() {

cat <<EOF
Usage:  $0 test advanced server [ -h ] [ -r ]

    Start up a netserver server for the use with flent clients.

    -h|--help           Show this help
    -r|--reverse        Reverse roles i.e. use client as server
                        and thus start the server in namespace $CLIENT_NAMESPACE
EOF

}

test__advanced__server() {
    reverse=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__advanced__server__help
                return 0
                ;;
            -r|--reverse)
                reverse=true
                shift
                ;;
            *)
                echo "Unknown option $1"
                test__advanced__server__help
                return 1
                ;;
        esac
    done

    if [[ "$reverse" == true ]]; then
        namespace="$CLIENT_NAMESPACE"
    else
        namespace="$SERVER_NAMESPACE"
    fi

    base_cmd="sudo ip netns exec $namespace"

    if [[ "$($base_cmd ss -ltn)" == *:12865* ]]; then
        echo "Server is already running."
        return 0
    fi

    cmd="$base_cmd netserver"

    echo "Executing: $cmd"
    echo

    bash -c "$cmd"
    return 0
}

TEST_ADVANCED_DEFAULT_TEST="rrul_up"
TEST_ADVANCED_DEFAULT_TIME="10"
TEST_ADVANCED_DEFAULT_STEP_SIZE="0.1"

test__advanced__client__help() {

cat <<EOF
Usage:  $0 test advanced [ -h ] [ -r ] [ -t time ] [ -s step_size ] flent_test_name

    Start up a flent client.

    -h|--help           Show this help
    -r|--reverse        Reverse roles i.e. use server as client
                        and thus start the client in namespace $SERVER_NAMESPACE
    -t|--time           Base test time in seconds (default: $TEST_ADVANCED_DEFAULT_TIME)
                        (flent may adjust this a bit for certain test cases)
    -s|--step-size      Step size for sampling (default: $TEST_ADVANCED_DEFAULT_STEP_SIZE)
                        (this is not very accurately realized by flent)

    flent_test_name     A name of a flent test configuration (default: $TEST_ADVANCED_DEFAULT_TEST)
EOF

}

test__advanced__client() {
    reverse=false
    time=""
    step_size=""
    positional_args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__advanced__client__help
                return 0
                ;;
            -r|--reverse)
                reverse=true
                shift
                ;;
            -t|--time)
                [ -z "$time" ] || { echo "Found option '$1' while already specified $time as the time."; return 1; }
                shift
                time="-l $1"
                shift
                ;;
            -s|--step-size)
                [ -z "$step_size" ] || { echo "Found option '$1' while already specified $step_size as the step size."; return 1; }
                shift
                time="-s $1"
                shift
                ;;
            -*|--*)
                echo "Unknown option $1"
                test__advanced__client__help
                return 1
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    if [[ "$reverse" == true ]]; then
        namespace="$SERVER_NAMESPACE"
        target="$CLIENT_IP"
    else
        namespace="$CLIENT_NAMESPACE"
        target="$SERVER_IP"
    fi

    if [[ "$time" == "" ]]; then
        time="-l $TEST_ADVANCED_DEFAULT_TIME"
    fi

    if [[ "$step_size" == "" ]]; then
        step_size="-s $TEST_ADVANCED_DEFAULT_STEP_SIZE"
    fi

    base_cmd="sudo ip netns exec $namespace flent -H $target"

    test_name="${positional_args[@]}"
    if [[ "$test_name" == "" ]]; then
        test_name="$TEST_ADVANCED_DEFAULT_TEST"
    fi

    cmd="$base_cmd $time $step_size $test_name"

    echo "Executing: $cmd"
    echo

    bash -c "$cmd"
    return 0

}

test__simple__help() {

cat <<EOF
Usage:  $0 test simple [ -h ]
        $0 test simple { help | server | client } [ subcommand options ]

    Simple network testing using iperf3.

    -h|--help           Show this help

    Subcommands:
        help            Show this help
        server          Start a iperf3 server
        client          Start a iperf3 client
EOF

}


test__simple() {
    local cmdname=$1
    if type "test__simple__$cmdname" >/dev/null 2>&1; then
        shift
        "test__simple__$cmdname" "$@"
        exit $?
    fi

    # no subcommand was called
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__simple__help 
                return 0
                ;;
            -*|--*)
                echo "Unknown option $1"
                test__simple__help 
                return 1
                ;;
            *)
                echo "Unknown subcommand $1"
                test__simple__help 
                return 1
                ;;
        esac
    done

    test__simple__help
    return 1
}

test__advanced__help() {

cat <<EOF
Usage:  $0 test advanced [ -h ]
        $0 test advanced { help | server | client } [ subcommand options ]

    Advanced network testing using flent.

    -h|--help           Show this help

    Subcommands:
        help            Show this help
        server          Start a netserver server
        client          Start a flent client
EOF

}

test__advanced() {
    local cmdname=$1
    if type "test__advanced__$cmdname" >/dev/null 2>&1; then
        shift
        "test__advanced__$cmdname" "$@"
        exit $?
    fi

    # no subcommand was called
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__advanced__help 
                return 0
                ;;
            -*|--*)
                echo "Unknown option $1"
                test__advanced__help 
                return 1
                ;;
            *)
                echo "Unknown subcommand $1"
                test__advanced__help 
                return 1
                ;;
        esac
    done

    test__advanced__help
    return 1
}

test() {
    is_vm=$([[ "$(uname -n)" == "ebpf" ]] && echo true || echo false)
    if [[ "$is_vm" == true ]]; then
        echo "All test commands must be executed on the host."
        return 1
    fi

    local cmdname=$1
    if type "test__$cmdname" >/dev/null 2>&1; then
        shift
        "test__$cmdname" "$@"
        exit $?
    fi

    # no subcommand was called
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                test__help
                return 0
                ;;
            -*|--*)
                echo "Unknown option $1"
                test__help
                return 1
                ;;
            *)
                echo "Unknown subcommand $1"
                test__help
                return 1
                ;;
        esac
    done

    test__help
    return 1
}

# call subcommand if it exists
if declare -f "$1" >/dev/null 2>&1; then
    "$@"
    exit "$?"
fi

# no subcommand was called
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            help
            exit 0
            ;;
        -*|--*)
            echo "Unknown option $1"
            help
            exit 1
            ;;
        *)
            echo "Unknown subcommand $1"
            help
            exit 1
            ;;
    esac
done

help
exit 1
