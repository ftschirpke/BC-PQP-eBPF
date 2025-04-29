# inspired by https://github.com/k8spacket/k8spacket/blob/master/Makefile

all: qemu

EBPF_SRC = bc-pqp-ebpf-kernel.c
USER_SRC = 
SHARED_SRC = 

# === BUILDING THE SOURCE CODE ===

SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include
LIB_DIR = lib
LIB_SRC_DIR = external

LLC = llc
CLANG = clang

INCLUDE = -I$(INCLUDE_DIR)/usr/include -I$(SRC_DIR)
WARN_FLAGS = -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror
SHARED_FLAGS = -O2

EBPF_HDR = 
USER_HDR = 
SHARED_HDR = 

LIBBPF_SRC_DIR = $(LIB_SRC_DIR)/libbpf/src
LIBXDP_SRC_DIR = $(LIB_SRC_DIR)/xdp-tools

LIBBPF_DIR = $(LIB_DIR)/libbpf
LIBBPF_OBJ = $(LIBBPF_DIR)/libbpf.a
LIBXDP_DIR = $(LIB_DIR)/libxdp
LIBXDP_OBJ = $(LIBXDP_DIR)/libxdp.a

EBPF_C = $(filter %.c, $(EBPF_SRC))
USER_C = $(filter %.c, $(USER_SRC))
SHARED_C = $(filter %.c, $(SHARED_SRC))
EBPF_OBJ = $(addprefix $(BUILD_DIR)/,$(EBPF_C:%.c=%.o))
USER_OBJ = $(addprefix $(BUILD_DIR)/,$(USER_C:%.c=%.o))
SHARED_OBJ = $(addprefix $(BUILD_DIR)/,$(SHARED_C:%.c=%.o))

$(LIBBPF_OBJ):
	mkdir -p $(LIBBPF_DIR)
	mkdir -p $(BUILD_DIR)
	mkdir -p $(INCLUDE_DIR)
	make all -C $(LIBBPF_SRC_DIR) OBJDIR=$(realpath $(LIBBPF_DIR))
	make install_headers -C $(LIBBPF_SRC_DIR) DESTDIR=$(realpath $(INCLUDE_DIR)) OBJDIR=$(realpath $(LIBBPF_DIR))

$(LIBXDP_OBJ):
	mkdir -p $(LIBXDP_DIR)
	make all -C $(LIBXDP_SRC_DIR) OBJDIR=$(realpath $(LIBXDP_DIR))

build: $(EBPF_OBJ)

$(EBPF_OBJ): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(LIBBPF_OBJ)
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(INCLUDE) \
	    $(WARN_FLAGS) \
	    -emit-llvm -c -g \
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

# === BUILDING THE VIRTUAL MACHINE ===

SU_DOCKER=$(shell id -nGz "${USER}" | grep -qzxF "docker" || echo sudo)
SU_LVIRTD=$(shell id -nGz "${USER}" | grep -qzxF "libvirtd" || echo sudo)
FLAVOR=virt

qemu/filesystem.qcow2: Dockerfile $(EBF_OBJ) $(LOAD_SCRIPT) $(STATUS_SCRIPT) $(UNLOAD_SCRIPT)
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 ${SU_DOCKER} docker build --build-arg FLAVOR=${FLAVOR} --output "type=tar,dest=qemu/filesystem.tar" .
	# extract kernel
	tar --extract --file=qemu/filesystem.tar boot/vmlinuz-${FLAVOR} boot/initramfs-${FLAVOR} boot/config-6.12.25-0-${FLAVOR}
	# convert tar to qcow2 image
	${SU_LVIRTD} virt-make-fs --partition --type=ext4 --format=qcow2 --size=+100M qemu/filesystem.tar qemu/filesystem.qcow2

qemu: build qemu/filesystem.qcow2
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
	-rm -f qemu/*.qcow2 qemu/*.tar build/* boot/*

.PHONY: qemu clean
