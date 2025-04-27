# https://github.com/k8spacket/k8spacket/blob/master/Makefile

filesystem.zip: Dockerfile
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 sudo docker build --output "type=tar,dest=filesystem.tar" .
	# convert tar to qcow2 image
	sudo virt-make-fs --format=qcow2 --size=+100M filesystem.tar filesystem-large.qcow2
	# reduce size of image
	qemu-img convert filesystem-large.qcow2 -O qcow2 filesystem.qcow2
	# reduce size by packing
	zip filesystem.zip filesystem.qcow2
	# remove unnecessary files
	rm -f filesystem-large.qcow2 filesystem.qcow2 filesystem.tar

qemu: filesystem.zip
	rm -f filesystem.qcow2 filesystem-diff.qcow2
	unzip ./filesystem.zip
	sudo qemu-img create -f qcow2 -b filesystem.qcow2 -F qcow2 filesystem-diff.qcow2
	PWD=$(pwd)
	sudo qemu-system-x86_64 \
	-cpu host \
	-m 4G \
	-smp 4 \
	-kernel ${PWD}/bzImage \
	-append "console=ttyS0 root=/dev/sda rw" \
	-drive file="${PWD}/filesystem-diff.qcow2,format=qcow2" \
	-enable-kvm \
	-pidfile qemu.pid \
	-nographic

.phony: qemu
