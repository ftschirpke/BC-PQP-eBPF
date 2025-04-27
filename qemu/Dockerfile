# inspired by https://github.com/k8spacket/k8spacket/blob/master/tests/e2e/vm/filesystem/Dockerfile

FROM ubuntu:24.04

RUN apt-get update \
    # install systemd as initialization module
    && apt-get install --no-install-recommends --no-install-suggests -y systemd \
    # install ssh to allow connect from outside
    && apt-get install -y openssh-server \
    # install net-tools to enable eth0 network interface
    && apt-get install --no-install-recommends --no-install-suggests -y net-tools \
    && rm -rf /var/lib/apt/lists/*

# switch initialization target from GUI (graphical.target) to text (multi-user.target) mode
RUN cd /lib/systemd/system && ln -sf multi-user.target default.target

# enable serial port to use for login
RUN systemctl enable getty@ttyS0.service
# enable ssh server
RUN systemctl enable ssh.service

# set root password
RUN echo "root:root" | chpasswd

# enable autologin on serial port
RUN sed -i 's/ExecStart=.*/ExecStart=-\/sbin\/agetty --noissue --autologin root %I $TERM/g' /lib/systemd/system/getty@.service
# keep boot messages on tty console
RUN sed -i 's/TTYVTDisallocate=yes/TTYVTDisallocate=no/g' /lib/systemd/system/getty@.service
# allow login as root through ssh
RUN sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config

# set hostname
RUN echo "ebpf" > /etc/hostname

