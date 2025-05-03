# inspired by https://github.com/k8spacket/k8spacket/blob/master/Makefile

all: qemu

EBPF_SRC = bc-pqp-ebpf-kernel.c
USER_SRC = 
SHARED_SRC = 

# === BUILDING THE SOURCE CODE ===

SRC_DIR = src
BUILD_DIR = build

LLC = llc
CLANG = clang

WARN_FLAGS = -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror
SHARED_FLAGS = -O2

EBPF_HDR = 
USER_HDR = 
SHARED_HDR = 

EBPF_C = $(filter %.c, $(EBPF_SRC))
USER_C = $(filter %.c, $(USER_SRC))
SHARED_C = $(filter %.c, $(SHARED_SRC))
EBPF_OBJ = $(addprefix $(BUILD_DIR)/,$(EBPF_C:%.c=%.o))
USER_OBJ = $(addprefix $(BUILD_DIR)/,$(USER_C:%.c=%.o))
SHARED_OBJ = $(addprefix $(BUILD_DIR)/,$(SHARED_C:%.c=%.o))

build: $(EBPF_OBJ) 

$(EBPF_OBJ): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(WARN_FLAGS) \
	    -emit-llvm -g \
		-o $(@:.o=.ll) $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)

NETWORK_INTERFACE = lo

LOAD_SCRIPT=$(BUILD_DIR)/load.sh
STATUS_SCRIPT=$(BUILD_DIR)/status.sh
UNLOAD_SCRIPT=$(BUILD_DIR)/unload.sh

$(LOAD_SCRIPT):
	echo "#!/bin/sh" > $@
	echo "xdp-loader load -m skb $(NETWORK_INTERFACE) $(EBPF_OBJ:$(BUILD_DIR)/%=%)" >> $@

$(STATUS_SCRIPT):
	echo "#!/bin/sh" > $@
	echo "xdp-loader status $(NETWORK_INTERFACE)" >> $@

$(UNLOAD_SCRIPT):
	echo "#!/bin/sh" > $@
	echo "if [ \$$# -ne 1 ]; then if=\"-a\"; else if=\"-i \$$1\"; fi" >> $@
	echo "xdp-loader unload $(NETWORK_INTERFACE) \$$if" >> $@

script: $(LOAD_SCRIPT) $(STATUS_SCRIPT) $(UNLOAD_SCRIPT)

# === BUILDING THE VIRTUAL MACHINE ===

SU_DOCKER=$(shell id -nGz "${USER}" | grep -qzxF "docker" || echo sudo)
SU_LVIRTD=$(shell id -nGz "${USER}" | grep -qzxF "libvirtd" || echo sudo)
KERNEL_VERSION=6.8.0-59-generic
KERNEL_NAME=boot/vmlinuz-${KERNEL_VERSION}
INITRD_NAME=boot/initrd.img-${KERNEL_VERSION}

qemu/filesystem.qcow2: Dockerfile $(EBF_OBJ) 
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 ${SU_DOCKER} docker build --output "type=tar,dest=qemu/filesystem.tar" .
	# extract kernel
	KERNEL_VERSION=6.8.0-59-generic
	tar --extract --file=qemu/filesystem.tar ${KERNEL_NAME} ${INITRD_NAME} boot/config-${KERNEL_VERSION}
	# convert tar to qcow2 image
	${SU_LVIRTD} virt-make-fs --type=ext4 --format=qcow2 --size=+100M qemu/filesystem.tar qemu/filesystem.qcow2

qemu: qemu/filesystem.qcow2
	${SU_LVIRTD} qemu-system-x86_64 \
		-cpu host \
		-m 4G \
		-smp 4 \
		-nic user \
		-kernel ./${KERNEL_NAME} \
		-initrd ./${INITRD_NAME} \
		-append "console=ttyS0 root=/dev/sda rw" \
		-hda ./qemu/filesystem.qcow2 \
		-enable-kvm \
		-pidfile ./qemu/qemu.pid \
		-nographic
clean:
	-rm -f qemu/*.qcow2 qemu/*.tar build/* boot/*

.PHONY: qemu clean
