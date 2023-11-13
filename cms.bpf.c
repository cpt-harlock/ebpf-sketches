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


struct cms_row_struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, CMS_SIZE);
        __type(key, __u32);
        __type(value, __u32);
}; 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, CMS_ROWS);
    __type(key, __u32);
    __array(values, struct cms_row_struct);
} cms_map SEC(".maps");


static inline int hash(char str[15]) {
	int hash = 5381;
	int c;
	int i = 0;

	while (i < 14) {
		i++;
		c = str[i];
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}
 
int counter = 0;

SEC("xdp")
int cms(struct xdp_md *ctx) {
    counter++;
    //bpf_printk("Counter %d", counter);
    //bpf_printk("Counter %d", counter);
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);
    struct ethhdr* eth_hdr = data;
    struct iphdr* ip_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;
    
    char key[15];
    uint parse = 0;
    __u32* val;
    __u32 new_val;
        new_val = 1;
        
    __u32 row_index = 0;
    __u32 row_index_old = 0;
    __u16 protocol = 0;
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    if (data + sizeof(struct ethhdr) < (void*)(long)ctx->data_end) {
    	protocol = eth_hdr->h_proto;
    	if (protocol == htons(ETH_P_IP) ) {
    		ip_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr));
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >=  data_end) 
			goto end;
    		src_ip = ip_hdr->saddr;
    		dst_ip = ip_hdr->daddr;
    		if (ip_hdr->protocol == IPPROTO_TCP) {
    			tcp_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr)+sizeof(struct iphdr));
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) >= data_end)
				goto end;
    			src_port = tcp_hdr->source;
    			dst_port = tcp_hdr->dest;
    			protocol = IPPROTO_TCP;
    	    		row_index = src_ip+dst_ip+dst_port+src_port+protocol;
    	    		parse = 1;
			*((__u32*)(&key[0])) = src_ip;
			*((__u32*)(&key[4])) = dst_ip;
			*((__u16*)(&key[8])) = src_port;
			*((__u16*)(&key[10])) = src_port;
			*((__u8*)(&key[12])) = IPPROTO_TCP;
    		}
    		else if (ip_hdr->protocol == IPPROTO_UDP) {
    			udp_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr)+sizeof(struct iphdr));
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) >= data_end)
				goto end;
    			src_port = udp_hdr->source;
    			dst_port = udp_hdr->dest;
    			protocol = IPPROTO_UDP;
    	    		row_index = src_ip+dst_ip+dst_port+src_port+protocol;
			*((__u32*)(&key[0])) = src_ip;
			*((__u32*)(&key[4])) = dst_ip;
			*((__u16*)(&key[8])) = src_port;
			*((__u16*)(&key[10])) = src_port;
			*((__u8*)(&key[12])) = IPPROTO_UDP;
    	    		parse = 1; 
    		} 
    	}
    } 
    key[14] = 0;
    if (parse) {
	for (int i = 0; i < CMS_ROWS; i++) {
		// update key
		key[13] = i;
		// get inner map
		struct cms_row_struct* inner_map;
		inner_map = bpf_map_lookup_elem(&cms_map, &i);
        	row_index = hash(key);
		row_index = (uint)row_index % (uint)CMS_SIZE;
        	row_index_old = src_ip+dst_ip+dst_port+src_port+protocol;
        	//row_index = 0;
        	bpf_printk("parse");
        	bpf_printk("key %s", key);
        	bpf_printk("index %d", row_index); 
        	bpf_printk("old_index %d", row_index_old); 
        	//bpf_map_update_elem(&cms, &row_index, &counter, BPF_ANY);
        	val = bpf_map_lookup_elem(&inner_map, &row_index);
        	if (val != NULL) {
        		new_val = (*val)+1;
        		bpf_map_update_elem(&inner_map, &row_index, &new_val, BPF_ANY);
        		bpf_printk("old val: %d update: %d", *val, new_val); 
        	} else {
        		bpf_printk("insert: val %d", new_val); 
        		bpf_map_update_elem(&inner_map, &row_index, &new_val, BPF_ANY);
		}
        	//bpf_printk("new val %d", new_val); 
	}
    }
    
end:
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
