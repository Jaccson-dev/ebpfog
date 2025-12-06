all: rootkit.bpf.o rootkit

rootkit.bpf.o: rootkit.bpf.c rootkit.h vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c $< -o $@

rootkit: rootkit.c rootkit.h
	gcc -O2 -g -Wall -o $@ $< -lbpf -lelf -lz

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f *.o rootkit vmlinux.h
