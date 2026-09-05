#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "ghostgate.h"

// Hash map for banned IP addresses (managed by userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);     // IPv4 address
    __type(value, __u8);    // 1 = Drop, 0 = Allow
} blocked_ips SEC(".maps");

// Ring buffer to stream flow telemetry to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} flow_events SEC(".maps");

SEC("xdp")
int ghostgate_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Verify Ethernet header bounds
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Verify IPv4 header bounds
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Check if the source IP is blocked in the eBPF map
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked == 1) {
        return XDP_DROP; // Drop packet immediately at the NIC level
    }

    // Inspect TCP specific parameters for fingerprinting
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            // Reserve a record in the ring buffer
            struct packet_event *event = bpf_ringbuf_reserve(&flow_events, sizeof(*event), 0);
            if (event) {
                event->src_ip = src_ip;
                event->dst_ip = ip->daddr;
                event->src_port = tcp->source;
                event->dst_port = tcp->dest;
                event->tcp_window = __constant_ntohs(tcp->window);
                event->timestamp = bpf_ktime_get_ns();
                bpf_ringbuf_submit(event, 0);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";