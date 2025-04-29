# inspired by https://github.com/k8spacket/k8spacket/blob/master/Makefile

SU_DOCKER=$(shell id -nGz "${USER}" | grep -qzxF "docker" || echo sudo)
SU_LVIRTD=$(shell id -nGz "${USER}" | grep -qzxF "libvirtd" || echo sudo)
# needs to correspond to the linux-$FLAVOR in the dockerfile
FLAVOR=virt

qemu/filesystem.qcow2: Dockerfile
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 ${SU_DOCKER} docker build --build-arg FLAVOR=${FLAVOR} --output "type=tar,dest=qemu/filesystem.tar" .
	# extract kernel
	tar --extract --file=qemu/filesystem.tar boot/vmlinuz-${FLAVOR} boot/initramfs-${FLAVOR} boot/config-6.12.25-0-${FLAVOR}
	# convert tar to qcow2 image
	${SU_LVIRTD} virt-make-fs --partition --type=ext4 --format=qcow2 --size=+100M qemu/filesystem.tar qemu/filesystem.qcow2

build:
	mkdir -p build
	echo "echo Hello" > build/hello.sh

all: qemu

qemu: build qemu/filesystem.qcow2
	# we need an initramfs because alpine loads all filesystem drivers as modules
	${SU_LVIRTD} qemu-system-x86_64 \
		-cpu host \
		-m 4G \
		-smp 4 \
		-nic user,model=virtio-net-pci \
		-kernel ./boot/vmlinuz-${FLAVOR} \
		-initrd ./boot/initramfs-${FLAVOR} \
		-append "rootfstype=ext4 console=ttyS0 root=/dev/sda1 rw" \
		-hda ./qemu/filesystem.qcow2 \
		-enable-kvm \
		-pidfile ./qemu/qemu.pid \
		-nographic
clean:
	-rm -f qemu/*.qcow2 qemu/*.tar build/*

.phony: qemu clean
