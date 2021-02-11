/*
 * @Author: calmwu
 * @Date: 2021-02-11 17:19:51
 * @Last Modified by: calmwu
 * @Last Modified time: 2021-02-11 20:51:42
 */

#include <stdio.h>
#include <linux/bpf.h>
#include <bpf_load.h>
#include <trace_helpers.h>

int main(int argc, char **argv) {
    if(load_bpf_file("kern_helloworld.o") != 0) {
        printf("The kernel didn't load the BPF program\n");
        return -1;
    }

    read_trace_pipe();

    return 0;
}

