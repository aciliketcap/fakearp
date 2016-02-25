/*
 * fakeARP.c
 * Copyright 2012 Sinan Akpolat
 *
 * A network driver which creates a network interface that captures ARP requests it receives
 * and responds with fake ARP responses using the data on the original ARP request.
 * Therefore it pretends to have a connection with some other network devices
 * on the other side of its cable. (it doesn't have a cable :)
 *
 * This file is distributed under GNU GPLv2, see LICENSE file.
 * If you haven't received a file named LICENSE see <http://www.gnu.org/licences>
 *
 * Fake ARP driver is distributed WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
 *
 * This is a code written solely for training purposes,
 * under any circumstances it should not be run on a production system.
 */

/*
 * This code is meant as a tutorial and does some stuff wrong, also doesn't do
 * some stuff it should be doing. I didn't introduce some features to keep it simple.
 * 1) It would be cooler if it used random mac addresses.
 * 2) add / remove IP - MAC pairs and show them from sysfs (debug with procfs first)
 * 3) write scripts to test these easily and share them
 */

#include <linux/module.h> //for init/exit macros
#include <linux/netdevice.h> //almost every struct, mainly net_device and associated functions
#include <linux/etherdevice.h> //alloc_etherdev
#include <linux/skbuff.h> //for skb structs and associated functions
#include <linux/spinlock.h> //we can't use any other mechanism since we will be locking at interrupt time mostly.
#include <linux/interrupt.h> //for using tasklets as a bottom-half mechanism
#include <linux/percpu.h> //per-cpu variables for holding stats
#include <linux/u64_stats_sync.h> //to sync 64bit per-cpu variables on 32bit archs

#include "fakeARP.h"

MODULE_LICENSE("GPL");

//--- ARP packet offsets ---//
#define etherdst  0  //destination ethernet address
#define ethersrc  6  //source ethernet address
#define isitARP   12 //2 bytes packet description. Should be 0x0806 if this is an ARP packet
#define ARPopts   14 //8 bytes long fixed ARP options
#define senderMAC 22 //source ethernet address
#define senderIP  28 //source IP address
#define targetMAC 32 //target ethernet address (zeroed in ARP requests)
#define targetIP  38 //target IP address
//ARP requests give targetIP and ask targetMAC
//ARP replies fill the MAC address and sends the same packet back
//we will be filling targetMAC with fake MACs and 
//make the whole packet look like it is coming from target MAC

//TODO: I need to re-check all these list stuff
//TODO: I also need a way to test it, it can't be done by using arping obviously
//packet queue element (we are using kernel linked lists for packet queues)
struct skb_list_node {
	struct sk_buff *skb;
	int processed;
	struct list_head node;
};

//this just prevents cache invalidation on all cpus when one cpu updates stats
//no performce gain since we are already locking for input / output lists
//I wanted to try out per-cpu variables
struct pcpu_lstats {
	u64 rx_packets;
	u64 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
	u64 tx_dropped;
	struct u64_stats_sync syncp;
};

extern struct list_head fake_mac_list[256];

struct net_device *fakedev = 0;	//TODO: this should be placed into priv section as a list to allow multiple devices
struct net_device_ops fakedev_ndo;
struct fake_priv {
	struct napi_struct napi; //napi_struct is held in priv section

	struct skb_list_node incoming_queue; //incoming skb queue
	spinlock_t incoming_queue_protector; //incoming queue protector between rx interrupt handler and tasklet
	struct skb_list_node outgoing_queue; //outgoing skb queue
	spinlock_t outgoing_queue_protector; //outgoing queue protector between tasklet and NAPI poller

	struct proc_dir_entry *fakearp_dump_entry; //better keep a pointer to it with the device
};

void fakeARP(unsigned long noparam);
DECLARE_TASKLET(forge_fake_reply, fakeARP, 0);  //we'll forge fake ARP replies in this tasklet ie. bottom half

//TODO: this is so ugly, can't I make it prettier by using macros or something?
//struct rtnl_link_stats64* (*ndo_get_stats64) hook
struct rtnl_link_stats64 *fakeARP_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *total_stats)
{
	u64 total_rx_packets = 0;
	u64 total_tx_packets = 0;
	u64 total_rx_bytes = 0;
	u64 total_tx_bytes = 0;
	u64 total_tx_dropped = 0;
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_lstats *tc_stats; //this cpu's stats
		u64 tc_rx_packets, tc_tx_packets, tc_rx_bytes, tc_tx_bytes, tc_tx_dropped; //this cpu's packet and byte counts
		unsigned int start; //for sync

		tc_stats = per_cpu_ptr(dev->lstats, i);
		do {
			start = u64_stats_fetch_begin_bh(&tc_stats->syncp);
			tc_rx_packets = tc_stats->rx_packets;
			tc_tx_packets = tc_stats->tx_packets;
			tc_rx_bytes = tc_stats->rx_bytes;
			tc_tx_bytes = tc_stats->tx_bytes;
			tc_tx_dropped = tc_stats->tx_dropped;
		} while (u64_stats_fetch_retry_bh(&tc_stats->syncp, start));

		printk(KERN_DEBUG "rx packets for cpu %d: %llu\n", i, tc_rx_packets);
		printk(KERN_DEBUG "tx packets for cpu %d: %llu\n", i, tc_tx_packets);
		printk(KERN_DEBUG "rx bytes for cpu %d: %llu\n", i, tc_rx_bytes);
		printk(KERN_DEBUG "tx bytes for cpu %d: %llu\n", i, tc_tx_bytes);
		printk(KERN_DEBUG "tx drops for cpu %d: %llu\n", i, tc_tx_dropped);

		total_rx_packets += tc_rx_packets;
		total_tx_packets += tc_tx_packets;
		total_rx_bytes   += tc_rx_bytes;
		total_tx_bytes   += tc_tx_bytes;
		total_tx_dropped += tc_tx_dropped;
	}

	printk(KERN_DEBUG "rx packets total: %llu\n", total_rx_packets);
	printk(KERN_DEBUG "tx packets total: %llu\n", total_tx_packets);
	printk(KERN_DEBUG "rx bytes total: %llu\n", total_rx_bytes);
	printk(KERN_DEBUG "tx bytes total: %llu\n", total_tx_bytes);
	printk(KERN_DEBUG "tx drops total: %llu\n", total_tx_dropped);

	total_stats->rx_packets = total_rx_packets;
	total_stats->tx_packets = total_tx_packets;
	total_stats->rx_bytes   = total_rx_bytes;
	total_stats->tx_bytes   = total_tx_bytes;
	total_stats->tx_dropped = total_tx_dropped;

	return total_stats;
}

//int (*ndo_open)(struct net_device *dev) hook
int fakeARP_open(struct net_device *dev) {
	struct fake_priv *tmp_priv = netdev_priv(dev);
	printk(KERN_NOTICE "setting fake arp device up!\n");

	napi_enable(&(tmp_priv->napi));
	printk(KERN_INFO "napi enabled for rx\n");

	netif_start_queue(dev);
	printk(KERN_INFO "tx queue enabled\n");

	return 0;
}

//int (*ndo_stop)(struct net_device *dev) hook
int fakeARP_stop(struct net_device *dev) {
	struct fake_priv *tmp_priv = netdev_priv(dev);

	napi_disable(&(tmp_priv->napi));
	printk(KERN_INFO"napi disabled\n");

	netif_stop_queue(dev);
	printk(KERN_INFO "tx queue disabled\n");

	printk(KERN_NOTICE "shutting fake arp device down\n");

	//TODO: we should also flush the queues here

	return 0;
}

//our napi poller function, without this we can't have kernel take packets from us
//int (*poll)(struct napi_struct *, int) hook
int fakeARP_poll(struct napi_struct *napi, int budget) {

	struct fake_priv *tmp_priv = netdev_priv(fakedev);
	struct pcpu_lstats *tc_stats; //this cpu's stats

	int ret; //to test if an skb is received correctly
	int poll_ret = 0; //return 0 if all packets are transferred

	struct skb_list_node *outgoing_skb;
	struct skb_list_node *next_skb; //for safe list traversal

	//please don't preempt me while I use a pointer specific to this cpu
	tc_stats = get_cpu_ptr(fakedev->lstats);

	spin_lock(&tmp_priv->outgoing_queue_protector);

	list_for_each_entry_safe(outgoing_skb, next_skb, &tmp_priv->outgoing_queue.node, node) 	{
		if(budget > 0) {
			if(outgoing_skb->skb != NULL) { //don't delete the starting node, we use it to access the queue!
				printk(KERN_DEBUG "here is the fake ARP reply I'll feed to NAPI :\n");
				print_hex_dump(KERN_DEBUG, ":", 1, 16, 1, outgoing_skb->skb->data, outgoing_skb->skb->len, true); //print_hex_dump_bytes modified

				ret = netif_receive_skb(outgoing_skb->skb);	//give the fake ARP reply to kernel

				if(ret==NET_RX_SUCCESS) {
					printk(KERN_INFO "fake arp reply skb fed to NAPI\n");

					//just for 64bit per cpu variables if we are on 32 bit arch
					u64_stats_update_begin(&tc_stats->syncp);
					tc_stats->rx_bytes += outgoing_skb->skb->len;
					tc_stats->rx_packets++;
					u64_stats_update_end(&tc_stats->syncp);

					budget--;

					//just delete the node, don't delete the skb!
					list_del(&outgoing_skb->node);
				}
			}
		} else {
			poll_ret = 1;
		}
	}

	spin_unlock(&tmp_priv->outgoing_queue_protector);

	put_cpu_ptr(fakedev->lstats);

	napi_complete(&tmp_priv->napi); //we have given as many packets as we can

	if(poll_ret) napi_schedule(&tmp_priv->napi); //but we still have packets to give

	return poll_ret;
}

//our forging function called by the tasklet
void fakeARP(unsigned long noparam) {

	//we will be creating an ARP packet from bits
	__u8 *orgdata; //ARP request packet given to us to send over the cable
	__u8 *data;	//ARP reply packet we are going to forge and pretend it came from another host

	struct fake_priv *tmp_priv = netdev_priv(fakedev); //we'll use this only to schedule NAPI polling

	struct skb_list_node *outgoing_skb_node;
	struct skb_list_node *incoming_skb_node;
	struct skb_list_node *next_skb; //for safe list traversal

	u8 *my_mac;

	spin_lock(&tmp_priv->incoming_queue_protector);

	//process the list of arp requests
	list_for_each_entry_safe(incoming_skb_node, next_skb, &tmp_priv->incoming_queue.node, node) {
		if(incoming_skb_node->skb != NULL) {
			struct sk_buff *fake_skb = alloc_skb(42, GFP_KERNEL); //allocate a new skb for fake ARP response
			if(fake_skb==NULL) {
				printk(KERN_CRIT "unable to allocate new skb for the fake ARP packet\n");
				break;
			}
			skb_put(fake_skb, 42); //create enough data section for fake ARP packet
			memset(fake_skb, 0, 42); //zero it out

			orgdata = incoming_skb_node->skb->data; //original data section in the ARP request

			printk(KERN_DEBUG "beginning to forge fake ARP reply\n");
			data = fake_skb->data;

			//we'll fill data part with a valid ARP reply using the info in the ARP request
			//copy all data section first, then swap and change necessary fields
			memcpy(data, orgdata, 42);
			//TODO: We will hold our own fake ARP table in a later version
			memcpy(data, orgdata+ethersrc, 6); //copy src mac to dest mac field

			if((my_mac = get_mac(data+targetIP)) == 0) {
				printk(KERN_DEBUG "unable to find IP %pI4 in IP list, creating new IP - MAC pair\n", data+targetIP);
				if((my_mac = insert_new_ip_mac_pair(data+targetIP)) == 0) {
					printk(KERN_CRIT "unable to create new MAC for IP %pI4\n", data+targetIP);
					//leave incoming in the list, may be we can do it next time. Remove failed one.
					kfree_skb(fake_skb);

					return;
				}

			}

			memset(data+ethersrc, 0xcc, 6); //for now all IP owners claim their mac is cc:cc:cc:cc:cc:cc
			*(data+ARPopts+7) = 0x02; //ARP replies have last octet of opts = 2
			memcpy(data+senderMAC, my_mac, 6); //again fake IP owner mac
			memcpy(data+senderIP, orgdata+targetIP, 4); //copy asked IP addr to sender field
			memcpy(data+targetMAC, orgdata+senderMAC, 6); //copy sender MAC to target MAC
			memcpy(data+targetIP, orgdata+senderIP, 4); //copy sender IP to target IP

			//that's it, let's see our forged packet
			printk(KERN_DEBUG "here is the fake ARP reply I forged:\n");
			print_hex_dump(KERN_DEBUG, ":", 1, 16, 1, fake_skb->data, fake_skb->len, true); //print_hex_dump_bytes modified


			//add fake_skb to outgoing queue
			outgoing_skb_node = (struct skb_list_node*) kmalloc(sizeof(struct skb_list_node), GFP_KERNEL); //TODO: what if allocation fails here?
			outgoing_skb_node->skb = fake_skb;
			printk(KERN_DEBUG "new fake skb is ready to give\n");

			outgoing_skb_node->skb->protocol = eth_type_trans(outgoing_skb_node->skb, fakedev);
			//we need to call this before handing the packet over to kernel,
			//it fixes head, data, mac etc. fields in the skb so that it seems like an ethernet packet
			__net_timestamp(outgoing_skb_node->skb); //as if we just got it fresh, without a timestamp

			spin_lock(&tmp_priv->outgoing_queue_protector);
			list_add(&outgoing_skb_node->node, &tmp_priv->outgoing_queue.node);
			spin_unlock(&tmp_priv->outgoing_queue_protector);

			//we are done with the skb
			kfree(incoming_skb_node->skb);
			list_del(&incoming_skb_node->node);
		}
	}

	spin_unlock(&tmp_priv->incoming_queue_protector);

	napi_schedule(&tmp_priv->napi); //tell napi system we may have received packets and it should poll our device some time.

	printk(KERN_DEBUG "napi scheduled, waiting for poller to take the fake ARP reply\n");

	return;   //success
}

//netdev_tx_t (*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev) hook
//enum netdev_tx_t is defined in netdevice.h
netdev_tx_t fakeARP_tx(struct sk_buff *skb, struct net_device *dev) {
	__u8 *data;
	int len;
	struct skb_list_node *incoming_skb_node;
	struct pcpu_lstats *tc_stats; //this cpu's stats
	struct fake_priv *tmp_priv = netdev_priv(fakedev);

	//please don't preempt me while I use a pointer specific to this cpu
	tc_stats = get_cpu_ptr(fakedev->lstats);

	len = skb->len;
	data = skb->data;

	//let's see what they want us to send (for debug)
	printk(KERN_DEBUG "I have received a packet:\n");
        print_hex_dump(KERN_DEBUG, ":", 1, 16, 1, skb->data, skb->len, true); //print_hex_dump_bytes modified

	//check if the packet is an ARP packet
	if(data[isitARP]==0x08 && data[isitARP+1]==0x06) { //2 octet long ethernet packet type part. 0x0806 is ARP
		//check if it is an ARP request
		if(data[ARPopts+6]==0x00 && data[ARPopts+7]==0x01) { //opcode 0x0001 is request, 0x0002 is reply

			//try to add skb to the list
			if(spin_trylock(&tmp_priv->incoming_queue_protector)) {

				struct sk_buff *incoming_skb = skb_clone(skb, GFP_ATOMIC);
				if(!incoming_skb) {
					printk(KERN_CRIT "failed to clone skb for forging\n");
					spin_unlock(&tmp_priv->incoming_queue_protector);
					return NETDEV_TX_BUSY; //if cloning fails give the packet back
				}

				incoming_skb_node = kmalloc(sizeof(struct skb_list_node), GFP_ATOMIC);
				incoming_skb_node->skb = incoming_skb;
				incoming_skb_node->processed = 0;

				list_add(&incoming_skb_node->node, &(tmp_priv->incoming_queue.node));
				spin_unlock(&tmp_priv->incoming_queue_protector);

				//forger tasklet will take care of the rest
				tasklet_schedule(&forge_fake_reply);
			} else {
				//queue is being used by the tasklet or another interrupt
				return NETDEV_TX_BUSY;
			}
		}
	}

	//just for 64bit per cpu variables if we are on 32 bit arch
	u64_stats_update_begin(&tc_stats->syncp);
	tc_stats->tx_bytes += len;
	tc_stats->tx_packets++;
	u64_stats_update_end(&tc_stats->syncp);

	put_cpu_ptr(fakedev->lstats);

	//even if the packet is not an ARP packet we'll tell we sent it over the cable though
	dev_kfree_skb_any(skb);
	//we used dev_kfree_skb_any because this function may run on int time or syscall time

	return NETDEV_TX_OK;
}

void fakeARP_exit_module(void) {
	if(fakedev) {
		struct fake_priv *tmp_priv;

		//TODO: cancel all the interrupts
		//TODO: unregister all the tasklets
		//TODO: then unregister the device
		//TODO: also rewrite device free function so that all dynamically allocated list elements are freed

		free_percpu(fakedev->lstats);

		tmp_priv = netdev_priv(fakedev);
		if(tmp_priv->fakearp_dump_entry)
			remove_proc_entry("fakearp_dump", NULL);

		unregister_netdev(fakedev); //also free's device and priv parts since we set fakedev->destructor to free_dev
	}
	return;
}

int fakeARP_init_module(void) {
	int ret = 0;
	int i = 0;
	struct fake_priv *tmp_priv; //after registering the device we'll access private section with this

	fakedev = alloc_etherdev(sizeof(struct fake_priv)); //just like alloc_dev but uses ether_setup to adjust a few ethernet related fields afterwards
	if(fakedev==NULL || fakedev == 0) {
		printk(KERN_CRIT "unable to allocate mem for fake ARP driver\n");
		return -ENOMEM;
	}
	printk(KERN_DEBUG "fakeARP driver struct allocated at addr: %p\n", fakedev);
	printk(KERN_DEBUG "its flags are set as %d by alloc_etherdev\n", fakedev->flags);

	//let's place necessary functions to the hooks
	fakedev->destructor = free_netdev; //called by unregister_device func. frees mem after unregistering
	fakedev_ndo.ndo_start_xmit = &fakeARP_tx;   //function to transmit packets to the other side of the cable
	fakedev_ndo.ndo_open = &fakeARP_open; //function used to "up" the device, ie. when user types ifconfig fkdev0 up
	fakedev_ndo.ndo_stop = &fakeARP_stop; //function used to "down" the device, ie. when user types ifconfig fkdev0 down
	fakedev_ndo.ndo_get_stats64 = &fakeARP_get_stats64; //function to get per cpu stats over rtnl

	fakedev->netdev_ops = &fakedev_ndo;

	//adjust mac addr and device name
	//TODO: change this code so that multiple devices are possible
	memcpy(fakedev->dev_addr, "\0AAAAAA", ETH_ALEN);
	strncpy(fakedev->name, "fkdev%d", IFNAMSIZ);

	tmp_priv = netdev_priv(fakedev); //now that we allocated the space, we can access our private section

	//init incoming packet queues and queue protectors
	tmp_priv->incoming_queue.skb = NULL; //queue head will always point to NULL
	tmp_priv->incoming_queue.processed = -1; //queue head will never be processed
	INIT_LIST_HEAD(&tmp_priv->incoming_queue.node);

	tmp_priv->outgoing_queue.skb = NULL;
	tmp_priv->outgoing_queue.processed = -1;
	INIT_LIST_HEAD(&tmp_priv->outgoing_queue.node);

	for(i=0;i<256;i++) {
		INIT_LIST_HEAD(&fake_mac_list[i]);
	}

	spin_lock_init(&tmp_priv->incoming_queue_protector);
	spin_lock_init(&tmp_priv->outgoing_queue_protector);

	fakedev->lstats = alloc_percpu(struct pcpu_lstats);

	//add the device to NAPI system
	netif_napi_add(fakedev, &(tmp_priv->napi), fakeARP_poll, 16); //16 is weight used for 10M eth

	//everything is set, register the device
	ret = register_netdev(fakedev);

	if(ret) {
		printk(KERN_CRIT "unable to register device. error code: %d\n", ret);
		return ret;
	}

	tmp_priv->fakearp_dump_entry = create_fakearp_dump_entry();

	return ret;
}

module_init(fakeARP_init_module);
module_exit(fakeARP_exit_module);
