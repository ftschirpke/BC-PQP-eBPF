#!/bin/sh

# as supposed to
# ping 192.168.100.2
# hping3 allows to ping with TCP and set the TCP SYN flag with '-S'
# which results in a random hardware queue to receive each packet
# (whereas all packets of one ping command are handled at the same queue)

# '-i 1' specifies interval of 1 second
sudo hping3 -S -p 80 -s 10000 -i 1 192.168.100.2

# '-i u1000' specifies interval of 1000 microseconds = 1 millisecond
# sudo hping3 -S -p 80 -s 10000 -i u1000 192.168.100.2

# '--flood' sends packets without interval
# sudo hping3 -S -p 80 -s 10000 --fload 192.168.100.2
