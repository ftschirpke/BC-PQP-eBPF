ARG ALPINE_REVISION=latest@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
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
# enable cgroups2 (might be necessary)
# RUN rc-update add cgroups boot
# mount root as shared (probably not necessary)
#RUN echo "/dev/sda1 / ext4 rw,relatime,rshared 0 1" >> /etc/fstab
# create bpffs mount, see https://github.com/cilium/cilium/blob/main/contrib/systemd/sys-fs-bpf.mount , (should probably not be done here but in sysfs)
#RUN echo "bpffs /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0" >> /etc/fstab
# see also https://superuser.com/questions/1845965/install-k3s-cilium-alpine
# this should be run after startup, no idea why openrc doesn't already do this (it should)
# once bpffs is mounted we get a new (fatal) error when loading the program
# RUN /etc/init.d/sysfs restart
COPY --from=build --chmod=700 /root/build/* /root/
