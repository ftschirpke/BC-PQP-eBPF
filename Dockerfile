# inspired by https://github.com/k8spacket/k8spacket/blob/master/tests/e2e/vm/filesystem/Dockerfile

FROM alpine:latest@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

RUN apk update \
    # kernel 
    && apk add linux-virt \
    # autologin
    && apk add agetty \ 
    # init system (used for networking)
    && apk add openrc

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
COPY build/hello.sh /root/

