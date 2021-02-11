#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv) {
    char path[PATH_MAX];
    sprintf(path, "%s/kern.o", dirname(argv[0]));

    int prog_fd;
    int ret;
    struct bpf_object *obj;

    if ((ret = bpf_prog_load(path, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd)) != 0) {
        printf("The kernel didn't load the BPF program, ret: %d, reason: %s\n", ret, strerror(ret));
        return -1;
    }

    if (prog_fd < 1) {
        printf("Error creating prog_fd\n");
        return -2;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "ebpf_kill_example");
    bpf_program__attach(prog);

    printf("eBPF will listen to force kills for the next 30 seconds!\n");
    sleep(30);

    struct bpf_map *kill_map = bpf_object__find_map_by_name(obj, "kill_map");
    int kill_map_fd = bpf_map__fd(kill_map);
    long key = -1, prev_key;

    // Iterate over all keys in the map
    while (bpf_map_get_next_key(kill_map_fd, &prev_key, &key) == 0) {
        printf("%ld was forcefully killed!\n", key);
        prev_key = key;
    }

    return 0;
}
