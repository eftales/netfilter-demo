
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/string.h>

static struct nf_hook_ops *nfho = NULL;
#define GNTAG "[GN-CYF]: " 

#define MAXLEN 2000

#define PACKET_IN_ETH_TYPE 0x09ad

#define IP_CONTROLLER "10.1.1.13"
#define LSC_ADD_INTERFACE "p4lo"
#define LSC_ETH_TYPE 0x09ab
#define LSC_HEAD_LEN 2
struct lsc_head_t{
	// unsigned char data[8];
	unsigned short ingress_port;
};

static unsigned int addLSCHead(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out,int (*okfn)(struct sk_buff *))
// static unsigned int addLSCHead(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb || strcmp(LSC_ADD_INTERFACE,skb->dev->name) != 0)
		return NF_ACCEPT;



	struct ethhdr *mh = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph;
	struct tcphdr *tcph;

	mh->h_proto = htons(PACKET_IN_ETH_TYPE);
	skb->head[12] = 0x99;
	printk(KERN_INFO GNTAG "src_mac = %x:%x:%x:%x:%x:%x\n",mh->h_source[0],mh->h_source[1],mh->h_source[2],mh->h_source[3],mh->h_source[4],mh->h_source[5]);  
	printk(KERN_INFO GNTAG "dest_mac = %x:%x:%x:%x:%x:%x\n",mh->h_dest[0],mh->h_dest[1],mh->h_dest[2],mh->h_dest[3],mh->h_dest[4],mh->h_dest[5]);  
	printk(KERN_INFO GNTAG "^_^\n");

	return NF_ACCEPT;

    int src_port ;
	int dest_port;
	char src_ip[64];
	char dest_ip[64];
 
	printk(KERN_INFO GNTAG "id: %d, protocol: %d, ttl: %d",iph->id, iph->protocol,iph->ttl);
	return NF_ACCEPT;

	// get port
	if (iph->protocol == IPPROTO_UDP)
	{	
		udph = udp_hdr(skb);
		dest_port = ntohs(udph->dest);
		src_port = 	ntohs(udph->source);

	}else if (iph->protocol == IPPROTO_TCP){
		tcph = tcp_hdr(skb);
		dest_port = ntohs(tcph->dest);
		src_port = 	ntohs(tcph->source);
	}
	// get ip
	snprintf(src_ip, 16, "%pI4", &iph->saddr); 
	snprintf(dest_ip, 16, "%pI4", &iph->daddr); 
	printk(KERN_INFO GNTAG "dest_ip: %s\n",dest_ip);

	skb_put(skb, LSC_HEAD_LEN);




	if (strcmp(IP_CONTROLLER,dest_ip) == 0){
		// printk(KERN_INFO GNTAG "\n\
		// src_vlan_id: %s\n\
		// src_ip: %s\n\
		// src_port: %d\n\
		// dest_ip: %s\n\
		// dest_port: %d\n", 
		// skb->vlan_tci,
		// src_ip,
		// src_port,
		// dest_ip,
		// dest_port);

		unsigned char * ip = skb_header_pointer (skb, 0, 0, NULL);

		int data_len = skb->len;
		unsigned char* lsc = kmalloc(MAXLEN * sizeof(char), GFP_ATOMIC);
		memcpy(lsc + LSC_HEAD_LEN, ip, data_len);
		lsc[0] = 1;
		lsc[1] = 2;



		// add lsc filed
		skb_put(skb, LSC_HEAD_LEN);
		// memcpy(ip, lsc, data_len + LSC_HEAD_LEN);

		ip[0] = 1;
		ip[1] = 2;
		int i = 0;
		for (i = 0;i<LSC_HEAD_LEN;++i){
			printk(KERN_INFO GNTAG "lsc %d = %d ",i,lsc[i]);  
		}
		printk(KERN_INFO GNTAG "\n"); 
		kfree(lsc);
	}

	return NF_ACCEPT;
}

static int __init  gn_cyf_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho->hook 	= (nf_hookfn*)addLSCHead;		
	nfho->hooknum 	= NF_INET_POST_ROUTING;	//  NF_INET_PRE_ROUTING NF_INET_POST_ROUTING NF_INET_LOCAL_OUT
	nfho->pf 	= PF_INET;			
	nfho->priority 	= NF_IP_PRI_FIRST;	
	
    printk(KERN_INFO GNTAG " registered\n");

	nf_register_net_hook(&init_net, nfho);
	return 0;
}

static void __exit gn_cyf_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	printk(KERN_INFO GNTAG " bye\n");
	kfree(nfho);
}

module_init(gn_cyf_init);
module_exit(gn_cyf_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giay Nhap");
MODULE_DESCRIPTION("CYF Driver");
