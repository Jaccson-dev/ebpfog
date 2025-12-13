// SPDX-License-Identifier: GPL-2.0
#ifndef __ROOTKIT_H__
#define __ROOTKIT_H__

/* vmlinux.h provides these for BPF, define for userspace */
#ifndef __VMLINUX_H__
#ifndef __u8
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#endif
#endif

#define BPF_PROG_LOAD         5
#define BPF_PROG_GET_NEXT_ID  11
#define BPF_MAP_CREATE        0
#define BPF_MAP_GET_NEXT_ID   12

enum {
    ACTION_PROG_CHANGED = 0,
    ACTION_MAP_CHANGED = 1,
};

struct event_data {
    __u8 action;
    __u32 pid;
    __u32 fd;
};

struct call_ctx { __u64 uattr_ptr; __u32 start_id; };

#define RINGBUF_SIZE     (256 * 1024)
#define MAX_HIDDEN_PROGS 10240
#define MAX_HIDDEN_MAPS  10240
#define MAX_CTX_ENTRIES  1024

#endif
