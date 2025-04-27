# inspired by https://github.com/k8spacket/k8spacket/blob/master/Makefile

qemu/filesystem.qcow2: Dockerfile
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 sudo docker build --output "type=tar,dest=qemu/filesystem.tar" .
	# convert tar to qcow2 image
	sudo virt-make-fs --format=qcow2 --size=+100M qemu/filesystem.tar qemu/filesystem-large.qcow2
	# reduce size of image
	qemu-img convert qemu/filesystem-large.qcow2 -O qcow2 qemu/filesystem.qcow2

build:
	mkdir -p build
	echo "echo Hello" > build/hello.sh

all: qemu

qemu: build qemu/filesystem.qcow2
	rm -f qemu/filesystem-diff.qcow2
	sudo qemu-img create -f qcow2 -b filesystem.qcow2 -F qcow2 qemu/filesystem-diff.qcow2
	sudo qemu-system-x86_64 \
		-cpu host \
		-m 4G \
		-smp 4 \
		-kernel ./qemu/bzImage \
		-append "console=ttyS0 root=/dev/sda rw" \
		-drive file="./qemu/filesystem-diff.qcow2,format=qcow2" \
		-enable-kvm \
		-pidfile ./qemu/qemu.pid \
		-nographic

.phony: qemu
