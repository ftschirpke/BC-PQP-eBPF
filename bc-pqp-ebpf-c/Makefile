
BUILD_DIR = build
LIB_DIR = .

LLC = llc
CLANG = clang
CC = gcc

EBPF_SRC = src/bc-pqp-ebpf-kernel.c
USER_SRC = 
SHARED_SRC = 

CFLAGS = -I$(LIB_DIR)/install/include
EBPF_CFLAGS = -I$(LIB_DIR)/install/include
WARN_CFLAGS = -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror
LDFLAGS = -L$(LIB_DIR)/install/lib

EBPF_HDR = 
USER_HDR = 
SHARED_HDR = 

LIBBPF_DIR = libbpf/src
LIBXDP_DIR = xdp-tools

LIBBPF_OBJ = $(LIBBPF_DIR)/install/lib/libbpf.a
LIBXDP_OBJ = $(LIBXDP_DIR)/install/lib/libxdp.a

EBPF_C = $(filter %.c, $(EBPF_SRC))
USER_C = $(filter %.c, $(USER_SRC))
SHARED_C = $(filter %.c, $(SHARED_SRC))
EBPF_OBJ = $(addprefix $(BUILD_DIR)/,$(EBPF_C:%.c=%.o))
USER_OBJ = $(addprefix $(BUILD_DIR)/,$(USER_C:%.c=%.o))
SHARED_OBJ = $(addprefix $(BUILD_DIR)/,$(SHARED_C:%.c=%.o))

all: $(EBPF_OBJ)

$(LIBBPF_OBJ):
	cd $(LIBBPF_DIR) && 
	make all OBJDIR=. &&
	mkdir -p build &&
	make install_headers DESTDIR=build OBJDIR=.

$(LIBXDP_OBJ):
	cd $(LIBXDP_DIR) &&
	make all OBJDIR=.

$(EBPF_OBJ): $(BUILD_DIR)/%.o: %.c $(LIBBPF_OBJ)
	@mkdir -p $(dir $@)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(EBPF_CFLAGS) \
	    $(WARN_CFLAGS) \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

