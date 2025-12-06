// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/__x64_sys_bpf")
int test_kprobe(struct pt_regs *ctx)
{
    bpf_printk("TEST: kprobe on __x64_sys_bpf triggered!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

