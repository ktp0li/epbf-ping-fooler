//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <stddef.h>
#include <stdlib.h>

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

#define MAX_CSUM_WORDS 750

// thanks Z17 from stackoverflow [https://stackoverflow.com/questions/20428578/calculating-icmp-packet-checksum] for func header
static __always_inline long compute_icmp_checksum(const void* data, __u16 size, const void* data_end) {
    const __u16* data_u16 = (const __u16 *)data;
    __u32 checksum = 0;
    bpf_printk("%d", size);

// FUCK THIS SHIT I HATE IT I SUFFERED SO MUCH WHILE TRYING TO SWITCH BETWEEN UNROLLED LOOP AND GENERIC LOOP (bpf_for for example).
// BUT IVE GOT VERIFIER'S CORNER CASE [https://stackoverflow.com/questions/70873332/invalid-access-to-packet-even-though-check-made-before-access] 
    #pragma unroll
    for (__u32 i = 0; i < MAX_CSUM_WORDS; i++) {
        bpf_printk("%d", i);
        if (2*i + 1 >= size) {
            break;
        }

        if (data + 2*i + 1 + 1 > data_end) {
            return 0; /* should be unreachable */
        }

        bpf_printk("%04x", __builtin_bswap16(data_u16[i]));
        checksum +=  __builtin_bswap16(data_u16[i]);
 //       if (2*i + 1 == size) {
 //            if (data + (i*2+2) > data_end) {
 //               return 0;
 //           }else{
 //               checksum += ((const __u8*)data)[i*2+1];
 //               return checksum;
 //           }
        }
        checksum = (checksum >> 16) + (checksum & 0xffff);

    return __builtin_bswap16((__u16)(~checksum));
}

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

    // send packet size to userspace
    bpf_printk("pkt len: %d", packet_len);
    bpf_map_update_elem(&pkt_len, &key, &packet_len, BPF_ANY);

    // increment packet count
    __sync_fetch_and_add(&pkt_count, 1); 

    struct icmp_packet *icmp_pkt = (struct icmp_packet *)(ip + 1);
    if ((void *)(icmp_pkt + 1) > data_end) {
        return XDP_PASS;
    }

    // check if icmp packet is reply to echo
    if (icmp_pkt->code != ICMP_TYPE_REPLY) {
        return XDP_PASS;
    }
 
    void* icmp_pkt_data = (void *)(icmp_pkt + 1);
    // does icmp data have 16 bytes of timestamp
    if ((void *)(icmp_pkt_data + 16) > data_end) {
        return XDP_PASS;
    }

    // replace timestamp in packet with garbage
    __u32 random_timestamp1 = bpf_get_prandom_u32();
    __u32 random_timestamp2 = bpf_get_prandom_u32();

    ((__u32 *)icmp_pkt_data)[0] = random_timestamp1;
    ((__u32 *)icmp_pkt_data)[1] = random_timestamp2;

    // flush checksum to recheck it
    icmp_pkt->checksum = 0;
    __u16 checksum = compute_icmp_checksum((void *)icmp_pkt, packet_len - 20 - 14, data_end);
    icmp_pkt->checksum = checksum;

    bpf_printk("checksum: %08x", checksum);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";