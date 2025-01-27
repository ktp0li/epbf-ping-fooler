//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 256 * 4096);
} packet_info_buf SEC(".maps");

struct packet_info {
    __u32 length;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 id; 
    __u16 seq;
    __u8 ttl;
    struct timeval old_timestamp;
    struct timeval new_timestamp;
} __attribute__((packed));

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
    if ((void *)(icmp_pkt_data + sizeof(__u128)) > data_end) {
        return XDP_PASS;
    }

    bpf_map_update_elem(&pkt_len, &key, &packet_len, BPF_ANY);

    // increment packet count
    __sync_fetch_and_add(&pkt_count, 1); 

    // values for sending packet info to userspace
    int64_t old_timestamp_sec = ((int64_t *)icmp_pkt_data)[0];
    int64_t old_timestamp_msec = ((int64_t *)icmp_pkt_data)[1];

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

    // send packet info to userspace
    struct packet_info *cur_pkt_info = bpf_ringbuf_reserve(&packet_info_buf, sizeof(struct packet_info), 0);
    if (!cur_pkt_info) {
        return XDP_PASS;
    }
    cur_pkt_info->dst_ip = ip->daddr;
    cur_pkt_info->src_ip = ip->saddr;

    cur_pkt_info->id = icmp_pkt->identifier;
    cur_pkt_info->length = packet_len;
    cur_pkt_info->seq = icmp_pkt->seq_number;
    cur_pkt_info->ttl = ip->ttl;

    cur_pkt_info->old_timestamp.tv_sec = old_timestamp_sec;
    cur_pkt_info->old_timestamp.tv_usec = old_timestamp_msec;

    cur_pkt_info->new_timestamp.tv_sec = ((int64_t *)icmp_pkt_data)[0];
    cur_pkt_info->new_timestamp.tv_usec = ((int64_t *)icmp_pkt_data)[1];

    bpf_printk("%08x, %08x", ((int64_t *)icmp_pkt_data)[0], ((int64_t *)icmp_pkt_data)[1]);
    bpf_printk("%lld, %lld", ((int64_t *)icmp_pkt_data)[0], ((int64_t *)icmp_pkt_data)[1]);

    bpf_ringbuf_submit(cur_pkt_info, 0);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
