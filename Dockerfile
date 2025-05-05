# inspired by https://github.com/k8spacket/k8spacket/blob/master/tests/e2e/vm/filesystem/Dockerfile

FROM ubuntu:24.04@sha256:f8b860e4f9036f2694571770da292642eebcc4c2ea0c70a1a9244c2a1d436cd9 AS base

RUN apt-get update

FROM base AS build

RUN apt-get install -y linux-headers-virtual clang llvm libelf-dev libbpf-dev libxdp-dev make gcc-multilib

COPY ./src /root/src
COPY ./Makefile /root/Makefile
WORKDIR /root
RUN make build

FROM base AS vm

# install systemd as initialization module
RUN apt-get install --no-install-recommends --no-install-suggests -y systemd
# install net-tools to enable eth0 network interface
RUN apt-get install --no-install-recommends --no-install-suggests -y net-tools
# install ssh to allow connect from outside
RUN apt-get install -y openssh-server
# install send and observe packets
RUN apt-get install -y iputils-ping tcpdump iproute2 xdp-tools
# tmux
RUN apt-get install -y tmux

RUN rm -rf /var/lib/apt/lists/*

# switch initialization target from GUI (graphical.target) to text (multi-user.target) mode
RUN cd /lib/systemd/system && ln -sf multi-user.target default.target

# enable serial port to use for login
RUN systemctl enable getty@ttyS0.service
# enable ssh server
RUN systemctl enable ssh.service

# enable autologin on serial port
RUN sed -i 's/ExecStart=.*/ExecStart=-\/sbin\/agetty --noissue --autologin root %I $TERM/g' /lib/systemd/system/getty@.service

# enable eth0
RUN cat <<EOF >> /etc/systemd/system/eth0.service
    [Unit]
    Description=eth0 service

    [Service]
    User=root
    WorkingDirectory=/root
    Type=oneshot
    ExecStart=ifconfig eth0 10.0.2.15 netmask 255.255.255.0
    ExecStart=route add default gw 10.0.2.2
    ExecStart=/bin/bash -c '/usr/bin/echo nameserver 8.8.8.8 > /etc/resolv.conf'
    ExecStart=/bin/bash -c '/usr/bin/echo "10.0.2.15 ebpf.domain" >> /etc/hosts'
    ExecStart=/bin/bash -c '/usr/bin/echo "127.0.0.1 ebpf-tls12.domain" >> /etc/hosts'
    ExecStart=/bin/bash -c '/usr/bin/echo "10.0.2.15 ebpf-tls13.domain" >> /etc/hosts'

    [Install]
    WantedBy=multi-user.target
EOF
RUN systemctl enable eth0.service

# disable welcome prompt
RUN echo "" > /etc/motd

# set hostname
RUN echo "ebpf" > /etc/hostname

COPY --from=build /root/build/* /root/
COPY --chmod=700 scripts /root/

