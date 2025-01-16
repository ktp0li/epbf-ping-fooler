//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>

volatile int pkt_count;
const int ICMP_TYPE_REPLY = 0;

struct icmp_packet {
    __u8 type;
    __u8 code;
    __be16  checksum;
    __be16 identifier;
    __be16 seq_number;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 


    __type(key, __u32);
    __type(value, int);
    __uint(max_entries, 1);
} pkt_len SEC(".maps");

SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
     // Pointers to packet data
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int packet_len = data_end - data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if the packet is IP (IPv4)
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Cast to IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // check is the packet is ICMP
    if (ip->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    __u32 key = 0;

    struct icmp_packet *icmp_pkt = (struct icmp_packet *)(ip + 1);
    if ((void *)(icmp_pkt + 1) > data_end) {
        return XDP_PASS;
    }

    // check if icmp packet is reply to echo
    if (icmp_pkt->type != ICMP_TYPE_REPLY) {
        return XDP_PASS;
    }

    void* icmp_pkt_data = (void *)(icmp_pkt + 1);
    // does icmp data have 16 bytes of timestamp
    if ((void *)(icmp_pkt_data + sizeof(__u64)) > data_end) {
        return XDP_PASS;
    }

    // send packet size to userspace
    bpf_printk("pkt len: %d", packet_len);
    bpf_map_update_elem(&pkt_len, &key, &packet_len, BPF_ANY);

    // increment packet count
    __sync_fetch_and_add(&pkt_count, 1); 

    // replace timestamp in packet with garbage
    __u32 old_timestamp = ntohl(((__u32 *)icmp_pkt_data)[0]);
    __u32 new_timestamp = bpf_get_prandom_u32() % 1730000000;
    ((__u32 *)icmp_pkt_data)[0] = new_timestamp;

    // recompute checksum
    __u32 new_checksum = ntohs(icmp_pkt->checksum);

    for (unsigned int i = 0; i <= 1; i++) {
        new_checksum += ((__u16 *)&old_timestamp)[i] + (~ntohs(((__u16 *)&new_timestamp)[i]) & 0xffff);
        new_checksum = (new_checksum & 0xffff) + (new_checksum>>16);
        icmp_pkt->checksum = htons(new_checksum + (new_checksum>>16));
    }

    bpf_printk("%16x", new_checksum);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
