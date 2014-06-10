/*
 * WARNING : this is not a kernel exploitation challenge !!
 * it's a port knocker firewall running in the kernel space 
 * break it out and get a shell running on port 4444
 * level by : Simo36 
 * good luck
 */

#include <net/ip.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#define NR_KNOCKS	5

#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#define __KERNEL__

MODULE_AUTHOR("Mohamed Ghannam");
MODULE_DESCRIPTION("FW Port knocker");
MODULE_LICENSE("GPLv2");

struct knocker {
    struct list_head list;
    __u32 ip;
    unsigned char knock_port_idx;
    unsigned int level2;
};

#define XORK1 0xdeadb00b
#define MAGIC1 0x12F9BC11
#define MAGIC 0x1234
#define N_KNOCKS 5
#define MAX_KEYLEN 64
#define DEBUG 1
#define FLUSH_COUNT 1000

/* My own firewall protocol */
struct fwhdr{
    unsigned int final_k[10];
};

u_short ports[5] = {1111,1112,1113,1114,1115};
struct list_head white_list;
struct list_head knocker_list;
int knockers=0;

static  int is_in_ports(__u16 port){
    int i;

    for(i = 0; i < NR_KNOCKS; i++){
        if(ports[i] == port){
            return 1;
        }
    }

    return 0;
}

long is_whitelisted(__u32 ip_addr){
	struct knocker * kr = NULL;
	struct list_head * knock_list = NULL;

	list_for_each(knock_list, &white_list) {
		kr = list_entry(knock_list, struct knocker, list);
		if (ip_addr == kr->ip) {
			return 1;
		}
	}
	
	return 0;
}

long do_whitelist(__u32 ip_addr){
    struct knocker *kr = NULL;

    if(is_whitelisted(ip_addr)) return 0;

    if(!(kr = kzalloc(sizeof(struct knocker), GFP_ATOMIC))){
        return -1;
    }

    kr->ip = goodguy;

    list_add_tail(&(kr->list), &white_list);
    gg++;
    return 0;
}

struct knocker * get_knocker(__u32 hostip){
    struct list_head * knock_list = NULL;
    struct knocker * kr = NULL;

    list_for_each(knock_list, &knocker_list) {
	    kr = list_entry(knock_list, struct knocker, list);
	    if (hostip == kr->ip) {
		    return kr;
	    }
    }
    
    return NULL;

}

int reset_knocker(int a){
	struct list_head * kr_head = NULL;
	struct knocker *kr = NULL;	
	
	list_for_each(kr_head, &knocker_list) {
		kr = list_entry(kr_head, struct knocker, list);
		if (kr) {
			list_del(&kr->list);
			kfree(kr);
		}
	}
	return 0;
}

long add_knocker(__u32 hostip){
	struct knocker *kr = NULL;
	
	if(knockers == 100){
		printk(KERN_INFO "kfw: reseting the knocker\n");
		reset_knocker(0);
	}
	
	if(!(kr = kzalloc(sizeof(struct knocker), GFP_ATOMIC))){
		return -1;
	}
	kr->ip = hostip;
	list_add_tail(&(kr->list), &knocker_list);
	knockers++;   
	
	return 0;
}

unsigned int hooks_in(unsigned long hooknum,
		       struct sk_buff **skb,
		       const struct net_device *in,
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff*))
{
	struct fwhdr *fw_h;
	__u16 eth_type,currport;
	__u16 curr_ipaddr;
	struct ethhdr *eth_h;
	struct iphdr *ip_h;
	struct tcphdr *tcp_h;
	struct udphdr *udp_h;
	struct knocker *kr_curr;
	u_int32_t *u_buf;
	int i,nr=0;
	char *udp_buf;
	unsigned int key1 = 0, first, second, third, fourth;
	
	if (!skb)
		return NF_DROP;

	eth_h = eth_hdr(skb);
	eth_type = ntohs(eth_h->h_proto);
	
	if(eth_type != ETH_P_IP)
		return NF_ACCEPT;

	ip_h = ip_hdr(skb);
	if(ip_h->protocol == IPPROTO_TCP) {
		tcp_h = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
		currport = ntohs(tcp_h->dest);
		if( (currport < 1100) || (currport >1200) 
		    && (currport != 4444)) 
			return NF_ACCEPT;

	} else if (ip_h->protocol == IPPROTO_UDP) {
		udp_h = (struct udphdr *)(skb_network_header(skb)+ip_hdrlen(skb));
		currport = ntohs(udp_h->dest);
		if(currport != 5555)
			return NF_ACCEPT;
	}
	
	
	curr_ipaddr = ip_h->saddr;
	if(is_whitelisted(curr_ipaddr)) 
		return NF_ACCEPT;
	
	if(!get_knocker(curr_ipaddr)) 
		add_knocker(curr_ipaddr);
	
	if(ip_h->protocol == IPPROTO_TCP) {
		tcp_h = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
		currport = ntohs(tcp_h->dest);
		kr_curr = get_knocker(curr_ipaddr);
		
		if(!kr_curr) 
			return NF_DROP;

		nr = kr_curr->knock_port_idx;
		
		if(nr == NR_KNOCKS) 
			/* if you reach this, you skipped the first rule !
			 * keep going :-)
			 */
			return NF_DROP;
		
		if (currport == ports[nr]) 
			kr_curr->knock_port_idx++;
		else 
			kr_curr->knock_port_idx = 0;
		nr = kr_curr->knock_port_idx;
		
		if (is_in_ports(currport))
		    return NF_ACCEPT;
		    
	}

	/* UDP check  */
	if (ip_h->protocol == IPPROTO_UDP) {
		udp_h = (struct udphdr*)(skb_network_header(skb) +
					 ip_hdrlen(skb));
		
		udp_buf = (char*)(skb_network_header(skb) +
				  ip_hdrlen(skb)+sizeof(struct udphdr));
		
		fw_h = (struct fwhdr*)(skb_network_header(skb) + 
				       ip_hdrlen(skb) +
				       sizeof(struct udphdr));
		
		u_buf = (u_int32_t*)((u_int8_t*)fw_h+8);
		
		kr_curr = get_knocker(curr_ipaddr);
		if(!kr_curr)
			return NF_ACCEPT;
		
		if(kr_curr->level2 != 1){
			if(kr_curr->knock_port_idx != N_KNOCKS){
				return NF_ACCEPT;
			}
			
			memcpy(&key1, udp_buf, 4);
			nr = key1 ^ XORK1;
			
			/* level 2 done ;) */
			if(nr == MAGIC1)
				kr_curr->level2 = 1;
			
			return NF_ACCEPT;
		}else{
			first = u_buf[0] ^ u_buf[1];
			if(first != u_buf[2]) goto end;
			
			second = u_buf[3] & u_buf[4];
			if(second != u_buf[5]) goto end;
			
			third = u_buf[5] ^ u_buf[2] ^ u_buf[6] ^ u_buf[7];
			fourth = u_buf[8] ^ u_buf[9];
			
			if((third ^ fourth) != u_buf[10]) goto end;
			i = do_whitelist(curr_ipaddr);
			return NF_ACCEPT;
		}
		for(i=0;i<NR_KNOCKS;i++) {
			printk(KERN_INFO"[+] Port : %d\n",u_buf[i]);
		}
		
	}
	
end:
	return NF_DROP;
}
unsigned int hooks_out(unsigned long hooknum,
		       struct sk_buff **skb,
		       const struct net_device *in,
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff*))
{
	return NF_ACCEPT;
}


static struct nf_hook_ops nf_ops_in = {
	.owner = THIS_MODULE,
	.hook = (nf_hookfn*)hooks_in,
	.pf   = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,//NF_IP_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nf_ops_out = {
	.owner = THIS_MODULE,
	.hook = (nf_hookfn*)hooks_out,
	.hooknum = NF_INET_POST_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,

};
int init_module()
{
	nf_register_hook(&nf_ops_in);
	nf_register_hook(&nf_ops_out);
	printk("[+] nefilter hooker registred ! \n");
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&nf_ops_in);
	nf_unregister_hook(&nf_ops_out);
	printk("[+] netfilter hooker unregistred \n");
}
