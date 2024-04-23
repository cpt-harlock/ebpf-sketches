#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include "cms.h"


extern int bpf_sum(int a , int b) __ksym;
extern __u64 bpf_rdpmc(int counter) __ksym;
extern __u64 bpf_mykperf_read_rdpmc(__u8 counter__k) __ksym;

SEC("xdp")
int pass(struct xdp_md *ctx) {
//	__u64 instructions = bpf_mykperf_read_rdpmc(1);
//	//int a = 1;
//	//int b = 2;
//	//int c = bpf_sum(a, b);
//	int c = 0;
//	//for (int i = 0; i < 10000; i++) {
//	//    c += i;
//	//}
//	//instructions = bpf_rdpmc(1) - instructions;
//	//unsigned long boh = bpf_rdpmc(2);
//	__u64 instructions_new = bpf_mykperf_read_rdpmc(1);
//	unsigned long cycles = bpf_mykperf_read_rdpmc(0);
//	instructions_new = instructions_new - instructions;
//	bpf_printk("cpu: %u instructions: %lu\n", bpf_get_smp_processor_id(), instructions);
//	bpf_printk("cpu: %u cycles: %lu  instructions %lu \n", bpf_get_smp_processor_id(), cycles, instructions_new);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
