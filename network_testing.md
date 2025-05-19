# Network Testing

## iperf3

### VM as server

This setup using `iperf3` works really well out-of-the-box if you start the iperf server inside the VM.
But this approch may not flood the hardware queues evenly (for UDP).

Host:
```bash
# UDP
iperf3 -u -c 192.168.100.2 -b <rate> -t 30 -P 4 --get-server-output
# TCP
iperf3 -c 192.168.100.2 -B 192.168.100.1 -b <rate> -p 5201 -t 30 -P 4 --get-server-output
# -p flag is optional
# -B flag is optional
```

VM:
```bash
iperf3 -s
```

### Host as server

## xdp-trafficgen

`xdp-trafficgen` is better for flooding all the hardware queues evenly, but arguably shows worse statistics

Host:
```bash
ifname=$(brctl show br0 | grep br0 | awk '{ print $4 }')
# UDP
sudo xdp-trafficgen udp "${ifname}" -a fe80::5054:ff:fe80:2 -p 5201 -t 4 -I 1 -s 64
# TCP - careful: here -t 4 are not 4 threads but a timout of 4 seconds
# i.e. do not use this, as it is not multi-threaded
sudo xdp-trafficgen tcp fe80::5054:ff:fe80:2 -i "${ifname}" -p 5201 -t 4 -I 1
```

