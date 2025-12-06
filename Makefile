CLANG := $(firstword $(wildcard /usr/bin/clang-18 /usr/bin/clang-17 /usr/bin/clang-16 /usr/bin/clang-15 /usr/bin/clang))
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

ifeq ($(CLANG),)
$(error No clang found. Run: sudo apt install clang libbpf-dev libelf-dev)
endif

all: rootkit.bpf.o rootkit

rootkit.bpf.o: rootkit.bpf.c rootkit.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@

rootkit: rootkit.c rootkit.h
	gcc -O2 -g -Wall -o $@ $< -lbpf -lelf -lz

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f *.o rootkit vmlinux.h
