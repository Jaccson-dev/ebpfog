CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all clean

all: bpf_hook.o

# Compile the BPF program
bpf_hook.o: bpf_hook.c
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I/usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include \
		-c $< -o $@

clean:
	rm -f *.o

