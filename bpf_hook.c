// BCC eBPF program to hook bpf() syscall
#include <uapi/linux/ptrace.h>

#define BPF_PROG_GET_NEXT_ID 11

struct call_ctx {
    u64 uattr_ptr;
    u32 start_id;
};

BPF_HASH(ctx_map, u64, struct call_ctx, 1024);

int trace_bpf_entry(struct pt_regs *ctx)
{
    struct call_ctx call_ctx = {};
    unsigned long cmd, uattr;
    struct pt_regs *regs;
    u32 start_id = 0;
    
    regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &regs->di);
    bpf_probe_read_kernel(&uattr, sizeof(uattr), &regs->si);
    
    if ((int)cmd != BPF_PROG_GET_NEXT_ID)
        return 0;
    
    if (bpf_probe_read_user(&start_id, sizeof(start_id), (void *)uattr) != 0)
        return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    call_ctx.uattr_ptr = uattr;
    call_ctx.start_id = start_id;
    ctx_map.update(&pid_tgid, &call_ctx);
    
    return 0;
}

int trace_bpf_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct call_ctx *call_ctx = ctx_map.lookup(&pid_tgid);
    
    if (!call_ctx)
        return 0;
    
    int ret_val = PT_REGS_RC(ctx);
    if (ret_val == 0) {
        u32 next_id = 0;
        bpf_probe_read_user(&next_id, sizeof(next_id), (void *)(call_ctx->uattr_ptr + 4));
        
        u32 modified_id = next_id + 27;
        bpf_probe_write_user((void *)(call_ctx->uattr_ptr + 4), &modified_id, sizeof(modified_id));
        
        bpf_trace_printk("BPF_PROG_GET_NEXT_ID: start_id=%u next_id=%u->%u\n",
                         call_ctx->start_id, next_id, modified_id);
    }
    
    ctx_map.delete(&pid_tgid);
    return 0;
}
