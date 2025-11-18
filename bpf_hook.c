// clang-format off
// SPDX-License-Identifier: GPL-2.0
/* This is a BCC eBPF program - linter errors are expected */
// clang-format on
#include <uapi/linux/ptrace.h>

// Define BPF command we care about
#define BPF_PROG_GET_NEXT_ID 11

// Structure to store context between entry and exit
struct call_ctx {
    u64 uattr_ptr;
    u32 start_id;
};

// Map to track syscall context - BCC syntax
BPF_HASH(ctx_map, u64, struct call_ctx, 1024);

// Hook bpf syscall entry
// Note: __x64_sys_bpf receives struct pt_regs* as its only parameter
// The actual syscall args are stored IN that pt_regs structure
int trace_bpf_entry(struct pt_regs *ctx)
{
    u64 pid_tgid;
    struct call_ctx call_ctx = {};
    u32 start_id = 0;
    int cmd;
    void *uattr;
    struct pt_regs *regs;
    
    // __x64_sys_bpf(const struct pt_regs *regs)
    // First parameter is a pointer to the pt_regs containing syscall args
    regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    // Read syscall arguments from the pt_regs structure
    // di = first syscall arg (cmd), si = second arg (uattr)
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &regs->di);
    bpf_probe_read_kernel(&uattr, sizeof(uattr), &regs->si);
    
    // Only track BPF_PROG_GET_NEXT_ID (value is 11)
    if (cmd != BPF_PROG_GET_NEXT_ID)
        return 0;
    
    // Read start_id from userspace (at offset 0)
    if (bpf_probe_read_user(&start_id, sizeof(start_id), uattr) != 0)
        return 0;
    
    // Save context for exit hook
    pid_tgid = bpf_get_current_pid_tgid();
    call_ctx.uattr_ptr = (u64)uattr;
    call_ctx.start_id = start_id;
    
    ctx_map.update(&pid_tgid, &call_ctx);
    
    return 0;
}

// Hook bpf syscall exit
int trace_bpf_exit(struct pt_regs *ctx)
{
    u64 pid_tgid;
    struct call_ctx *call_ctx;
    int ret_val;
    u32 next_id = 0;
    
    pid_tgid = bpf_get_current_pid_tgid();
    
    // Look up saved context
    call_ctx = ctx_map.lookup(&pid_tgid);
    if (!call_ctx)
        return 0;
    
    // Get syscall return value
    ret_val = PT_REGS_RC(ctx);
    
    // Only print if syscall succeeded
    if (ret_val == 0) {
        // Read next_id from userspace (at offset 4)
        bpf_probe_read_user(&next_id, sizeof(next_id), 
                           (void *)(call_ctx->uattr_ptr + 4));
        
        // Print start_id and next_id
        bpf_trace_printk("BPF_PROG_GET_NEXT_ID: start_id=%u next_id=%u\n",
                   call_ctx->start_id, next_id);
    }
    
    // Clean up
    ctx_map.delete(&pid_tgid);
    
    return 0;
}
