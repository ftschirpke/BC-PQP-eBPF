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

$(EBPF_OBJ): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(WARN_FLAGS) \
	    -emit-llvm -c -g \
		-o $(@:.o=.ll) $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)

# === BUILDING THE VIRTUAL MACHINE ===

SU_DOCKER=$(shell id -nGz "${USER}" | grep -qzxF "docker" || echo sudo)
SU_LVIRTD=$(shell id -nGz "${USER}" | grep -qzxF "libvirtd" || echo sudo)

SCRIPTS = $(wildcard scripts/*)

qemu/filesystem.qcow2: Dockerfile $(EBF_OBJ) $(SCRIPTS)
	# build filesystem image and store as tar archive
	DOCKER_BUILDKIT=1 ${SU_DOCKER} docker build --output "type=tar,dest=qemu/filesystem.tar" .
	# convert tar to qcow2 image
	${SU_LVIRTD} virt-make-fs --format=qcow2 --size=+100M qemu/filesystem.tar qemu/filesystem-large.qcow2
	# reduce size of image
	qemu-img convert qemu/filesystem-large.qcow2 -O qcow2 qemu/filesystem.qcow2

qemu: qemu/filesystem.qcow2
	rm -f qemu/filesystem-diff.qcow2
	${SU_LVIRTD} qemu-img create -f qcow2 -b filesystem.qcow2 -F qcow2 qemu/filesystem-diff.qcow2
	${SU_LVIRTD} qemu-system-x86_64 \
		-cpu host \
		-m 4G \
		-smp 4 \
		-kernel ./qemu/bzImage \
		-append "console=ttyS0 root=/dev/sda rw" \
		-drive file="./qemu/filesystem-diff.qcow2,format=qcow2" \
		-enable-kvm \
		-pidfile ./qemu/qemu.pid \
		-netdev bridge,id=net0,br=br0,helper=/usr/lib/qemu/qemu-bridge-helper \
		-device e1000,netdev=net0 \
		-nographic
clean:
	-rm -f qemu/*.qcow2 qemu/*.tar build/*

.PHONY: qemu clean
