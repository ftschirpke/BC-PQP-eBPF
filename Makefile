# inspired by https://github.com/k8spacket/k8spacket/blob/master/Makefile

all: qemu

EBPF_SRC = bc-pqp-ebpf-kernel.c

# === BUILDING THE SOURCE CODE ===

RX_QUEUES ?= 4

SRC_DIR = src
BUILD_DIR = build

LLC = llc
CLANG = clang

C_FLAGS = -O2
WARN_FLAGS = -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wsign-compare -Wsign-conversion -Werror

EBPF_HDR = 

DEBUG_PREFIX = debug_

EBPF_C = $(filter %.c, $(EBPF_SRC))
EBPF_OBJ = $(addprefix $(BUILD_DIR)/,$(EBPF_C:%.c=%.o))
EBPF_DEBUG_OBJ = $(addprefix $(BUILD_DIR)/$(DEBUG_PREFIX),$(EBPF_C:%.c=%.o))
EBPF_OBJECTS = $(EBPF_OBJ) $(EBPF_DEBUG_OBJ)

build: $(EBPF_OBJECTS)

$(EBPF_OBJ): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-DRX_QUEUES=$(RX_QUEUES) \
		$(C_FLAGS) \
	    $(WARN_FLAGS) \
	    -emit-llvm -g \
		-o $(@:.o=.ll) $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)

$(EBPF_DEBUG_OBJ): $(BUILD_DIR)/$(DEBUG_PREFIX)%.o: $(SRC_DIR)/%.c
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-D DEBUG \
		-DRX_QUEUES=$(RX_QUEUES) \
		$(C_FLAGS) \
	    $(WARN_FLAGS) \
	    -emit-llvm -g \
		-o $(@:.o=.ll) $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)

# === BUILDING THE VIRTUAL MACHINE ===

SU_DOCKER=$(shell id -nGz "${USER}" | grep -qzxF "docker" || type podman &> /dev/null || echo sudo)
SU_LVIRTD=$(shell id -nGz "${USER}" | grep -qzxF "libvirtd" || echo sudo)
CNTNR_CMD=$(shell type podman &> /dev/null && echo podman || echo docker)
FLAVOR=virt

docker: Dockerfile $(EBF_OBJECTS)
	@mkdir -p $(BUILD_DIR)/qemu
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 ${SU_DOCKER} ${CNTNR_CMD} build --build-arg FLAVOR=${FLAVOR} --output "type=tar,dest=$(BUILD_DIR)/qemu/filesystem.tar" .
	# extract kernel
	tar --extract --file=$(BUILD_DIR)/qemu/filesystem.tar --wildcards "boot/*" --exclude=boot/boot --one-top-level=$(BUILD_DIR)

qemu/filesystem.qcow2: docker 
	# convert tar to qcow2 image
	${SU_LVIRTD} virt-make-fs --partition --type=ext4 --format=qcow2 --size=+100M $(BUILD_DIR)/qemu/filesystem.tar $(BUILD_DIR)/qemu/filesystem.qcow2
	sudo mv ./$(BUILD_DIR)/qemu/filesystem.qcow2 /var/lib/libvirt/images/bc-pqp-fs.qcow2
	sudo mv ./$(BUILD_DIR)/boot/vmlinuz-${FLAVOR} /var/lib/libvirt/images/bc-pqp-vmlinux-${FLAVOR}
	sudo mv ./$(BUILD_DIR)/boot/initramfs-${FLAVOR} /var/lib/libvirt/images/bc-pqp-initramfs-${FLAVOR}

qemu: qemu/filesystem.qcow2
	sudo virt-install \
		--name bc-pqp-ebpf \
		--transient \
		--destroy-on-exit \
		--vcpus $(RX_QUEUES) \
		--memory=4096 \
		--disk=/var/lib/libvirt/images/bc-pqp-fs.qcow2 \
		--boot kernel=/var/lib/libvirt/images/bc-pqp-vmlinux-${FLAVOR},initrd=/var/lib/libvirt/images/bc-pqp-initramfs-${FLAVOR},kernel_args="rootfstype=ext4 console=ttyS0 root=/dev/vda1 rw" \
		--network bridge=br1,driver.queues=$(RX_QUEUES) \
		--network bridge=br2,driver.queues=$(RX_QUEUES) \
		--os-variant=alpinelinux3.20 \
		--graphics none \
		--autoconsole text
		
clean:
	-rm -f qemu/*.qcow2 qemu/*.tar $(BUILD_DIR)/* boot/*

.PHONY: qemu clean
