# inspired by https://github.com/k8spacket/k8spacket/blob/master/Makefile

all: qemu

EBPF_SRC = bc-pqp-ebpf-kernel.c

# === BUILDING THE SOURCE CODE ===

SRC_DIR = src
BUILD_DIR = build

LLC = llc
CLANG = clang

C_FLAGS = -O2
WARN_FLAGS = -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror

EBPF_HDR = 

EBPF_C = $(filter %.c, $(EBPF_SRC))
EBPF_OBJ = $(addprefix $(BUILD_DIR)/,$(EBPF_C:%.c=%.o))

build: $(EBPF_OBJ) 

$(EBPF_OBJ): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
		$(C_FLAGS) \
	    $(WARN_FLAGS) \
	    -emit-llvm -g \
		-o $(@:.o=.ll) $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)

# === BUILDING THE VIRTUAL MACHINE ===

SU_DOCKER=$(shell id -nGz "${USER}" | grep -qzxF "docker" || echo sudo)
SU_LVIRTD=$(shell id -nGz "${USER}" | grep -qzxF "libvirtd" || echo sudo)
FLAVOR=virt

qemu/filesystem.qcow2: Dockerfile $(EBF_OBJ) 
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 ${SU_DOCKER} docker build --build-arg FLAVOR=${FLAVOR} --output "type=tar,dest=qemu/filesystem.tar" .
	# extract kernel
	tar --extract --file=qemu/filesystem.tar --wildcards "boot/*"
	# convert tar to qcow2 image
	${SU_LVIRTD} virt-make-fs --partition --type=ext4 --format=qcow2 --size=+100M qemu/filesystem.tar qemu/filesystem.qcow2
	sudo mv ./qemu/filesystem.qcow2 /var/lib/libvirt/images/bc-pqp-fs.qcow2
	sudo mv ./boot/vmlinuz-${FLAVOR} /var/lib/libvirt/images/bc-pqp-vmlinux-${FLAVOR}
	sudo mv ./boot/initramfs-${FLAVOR} /var/lib/libvirt/images/bc-pqp-initramfs-${FLAVOR}

qemu: qemu/filesystem.qcow2
	sudo virt-install \
		--name bc-pqp-ebpf \
		--transient \
		--destroy-on-exit \
		--vcpus 4 \
		--memory=4096 \
		--disk=/var/lib/libvirt/images/bc-pqp-fs.qcow2 \
		--boot kernel=/var/lib/libvirt/images/bc-pqp-vmlinux-${FLAVOR},initrd=/var/lib/libvirt/images/bc-pqp-initramfs-${FLAVOR},kernel_args="rootfstype=ext4 console=ttyS0 root=/dev/vda1 rw" \
		--network bridge=br0,driver.queues=4 \
		--os-variant=alpinelinux3.20 \
		--graphics none \
		--autoconsole text
		
clean:
	-rm -f qemu/*.qcow2 qemu/*.tar build/* boot/*

.PHONY: qemu clean
