#include <stdio.h>
#include <linux/bpf.h>
#include <net/ethernet.h>
#include <linux/if_vlan.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <net/if.h>
#include <bpf/bpf_endian.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("prog")
int xdp_ip_filter(struct xdp_md *ctx)
{
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int ip_src;
    int ip_dst;
    long int offset;
    short int eth_type;
    char info_fmt1[] = "Dst Addr: xx.xx.%d.%d";
    char info_fmt2[] = "Src Addr: xx.xx.%d.%d";
    char info_fmt3[] = "------------------";

    static int i = 0;
    static int j = 0;
    unsigned char *saddrpoint = 0;
    unsigned char *daddrpoint = 0;

    struct ethhdr *eth = data;
    offset = sizeof(*eth);

    unsigned int indexofeth0 = 3;
    unsigned int indexofeth1 = 5;


    if (data + offset > end) {
    return XDP_ABORTED;
    }
    eth_type = eth->h_proto;
   
    /* 这里其实是有缺陷的，直接把收到的所有报文都当做不带VLAN的IPV4报文去解析，但因为测试环境简单，里面的报文也简单，所以这个处理基本上也问题不大 */

    struct iphdr *iph = data + offset;
    offset += sizeof(struct iphdr);
    /*在读取之前，确保你要读取的子节在数据包的长度范围内  */
    if (iph + 1 > end) {
        return XDP_ABORTED;
    }
    /*ip_src = iph->saddr;*/
    ip_dst = bpf_htonl(iph->daddr);


    /*saddrpoint = (unsigned char*)(&ip_src);
    daddrpoint =(unsigned char*)(&ip_dst);*/
    
    /* 发往10.0.0.10的直接通过eth0发送出去 */
    if(ip_dst == 0xa00000a)
    {
        bpf_printk("=> 1");
        return bpf_redirect(indexofeth0,0);
    }

    /* 发往10.0.0.4的直接通过eth1发送出去 */
    // if(ip_dst == 0x400000a)
    if(ip_dst == 0xa001501)
    {
         bpf_printk("=> 2");
        return bpf_redirect(indexofeth1,0);
    }
    /* 其它报文上送内核协议栈处理 */
             bpf_printk("=> 3 %x",ip_dst);
    return XDP_PASS;
}

char __license[] __section("license") = "GPL";

