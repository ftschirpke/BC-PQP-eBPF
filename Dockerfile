ARG ALPINE_REVISION=3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
FROM alpine:${ALPINE_REVISION} AS build
RUN apk add linux-headers clang llvm elfutils-dev libbpf-dev xdp-tools make
COPY ./src /root/src
COPY ./Makefile /root/Makefile
WORKDIR /root
RUN make build script

# inspired by https://github.com/k8spacket/k8spacket/blob/master/tests/e2e/vm/filesystem/Dockerfile
FROM alpine:${ALPINE_REVISION}
ARG FLAVOR

# kernel, autologin, init system (used for networking)
RUN apk add linux-${FLAVOR} agetty openrc xdp-tools
# debug stuff, in a new layer to avoid unnecessary rebuilds
RUN apk add 

# enable serial port for login
RUN echo "ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100\n" >> /etc/inittab

# set root password
RUN echo "root:root" | chpasswd
# enable networking
RUN echo "auto lo" > /etc/network/interfaces
RUN echo "iface lo inet loopback" >> /etc/network/interfaces
RUN echo "auto eth0" >> /etc/network/interfaces
RUN echo "iface eth0 inet dhcp" >> /etc/network/interfaces
RUN rc-update add networking boot

# disable welcome prompt
RUN echo "" > /etc/motd

# set hostname
RUN echo "ebpf" > /etc/hostname
# create the bpffs
COPY --chmod=700 ./services/bpffs /etc/init.d/bpffs
RUN rc-update add bpffs boot

COPY --from=build --chmod=700 /root/build/* /root/
