ARG UBUNTU_REVISION=latest
FROM ubuntu:${UBUNTU_REVISION} AS base
# update packages once for build & vm so that they can never get out of sync
RUN apt update

FROM base AS build
RUN apt update
RUN apt install -y linux-headers-virtual clang llvm libelf-dev libbpf-dev xdp-tools make gcc-multilib
COPY ./src /root/src
COPY ./Makefile /root/Makefile
WORKDIR /root
RUN make build script

# inspired by https://github.com/k8spacket/k8spacket/blob/master/tests/e2e/vm/filesystem/Dockerfile
FROM base AS vm
# kernel, autologin, init system (used for networking)
RUN TZ=Etc/UTC apt install -y linux-image-virtual systemd init xdp-tools net-tools nano pahole
RUN update-initramfs -u
# debug stuff, in a new layer to avoid unnecessary rebuilds
# RUN apt install -y 

# switch initialization target from GUI (graphical.target) to text (multi-user.target) mode
RUN cd /lib/systemd/system && ln -sf multi-user.target default.target
# enable serial port to use for login
RUN systemctl enable getty@ttyS0.service
# set root password
RUN echo "root:root" | chpasswd
# set root password
RUN echo "root:root" | chpasswd
# enable autologin on serial port
RUN sed -i 's/ExecStart=.*/ExecStart=-\/sbin\/agetty --noissue --autologin root %I $TERM/g' /lib/systemd/system/getty@.service
# keep boot messages on tty console
RUN sed -i 's/TTYVTDisallocate=yes/TTYVTDisallocate=no/g' /lib/systemd/system/getty@.service

# enable eth0
RUN cat <<EOF >> /etc/systemd/network/eth0.network
    [Match]
    Name=eth0
    Type=ether

    [Network]
    DHCP=ipv4
EOF
#RUN systemctl enable eth0.network

# set hostname
RUN echo "ebpf" > /etc/hostname
COPY --from=build --chmod=700 /root/build/* /root/
