#ifndef __GHOSTGATE_H
#define __GHOSTGATE_H

struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 tcp_window;
    __u64 timestamp;
};

#endif