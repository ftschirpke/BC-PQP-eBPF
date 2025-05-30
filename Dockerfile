ARG ALPINE_REVISION=3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
FROM alpine:${ALPINE_REVISION} AS build
RUN apk add linux-headers clang llvm elfutils-dev libbpf-dev libxdp-dev xdp-tools make
COPY ./src /root/src
COPY ./Makefile /root/Makefile
WORKDIR /root
RUN make build

# inspired by https://github.com/k8spacket/k8spacket/blob/master/tests/e2e/vm/filesystem/Dockerfile
FROM alpine:${ALPINE_REVISION}
ARG FLAVOR

# kernel, autologin, init system (used for networking), network tools
RUN apk add linux-${FLAVOR} agetty openrc xdp-tools iproute2 iputils-ping tcpdump ethtool bash
RUN apk add hping3 --update-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing
# debug stuff, in a new layer to avoid unnecessary rebuilds
RUN apk add 

# enable serial port for login
RUN echo "ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100\n" >> /etc/inittab

# set root password
RUN echo "root:root" | chpasswd
# enable networking
COPY ./services/interfaces /etc/network/
RUN echo "net.ipv4.ip_forward=1" > /etc/sysctl.conf 
RUN rc-update add networking boot
RUN rc-update add sysctl boot

# disable welcome prompt
RUN echo "" > /etc/motd

# set hostname
RUN echo "ebpf" > /etc/hostname
# create the bpffs
COPY --chmod=700 ./services/bpffs /etc/init.d/bpffs
RUN rc-update add bpffs boot
# mount debug fs
RUN rc-update add sysfs boot
# remove services that don't work in our environment and aren't needed
RUN rm -f /etc/init.d/machine-id /etc/init.d/hwdrivers

COPY --from=build /root/build/* /root/
COPY --chmod=700 scripts/* /root/
