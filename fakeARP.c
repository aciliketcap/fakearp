/*
 * fakeARP.c
 * Copyright 2012 Sinan Akpolat
 *
 * A network driver which creates a network interface that captures ARP requests it receives
 * and responds with fake ARP responses using the data on the original ARP request.
 * Therefore it pretends to have a connection with some other network devices
 * on the other side of its cable. (it doesn't have a cable :)
 *
 * This file is distributed under GNU GPLv3, see LICENSE file.
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
 * 1) Normally we should use rx/tx queues but right now we're using
 * only one packet as a buffer. Any other packets we receive to send are dropped.
 * 2) Our code takes a tx packet and creates an rx packet using the info inside
 * as soon as it is told to send the packet.
 * However optimally this should be done by recording the tx packet elsewhere.
 * Then telling the kernel we sent it.
 * Then using the record to forge new rx packet in a tasklet.
 * We are doing too much at interrupt time!
 * 3) It would be cooler if it used random mac addresses.
 * And keep track of them, you know like a private arp table.
 * We're lying and we should be consistent.
 * Currently it just uses cc:cc:cc:cc:cc:cc as a MAC addr everytime
 * 4) A minor thing is normally device stats are increased in a per-CPU manner. But we
 * adjust them like any other variable since we are working one packet at a time.
 */

#include <linux/module.h> //for init/exit macros
#include <linux/kernel.h> //for printk and other stuff
#include <linux/netdevice.h> //almost every struct, mainly net_device and associated functions
#include <linux/etherdevice.h> //alloc_etherdev
#include <linux/skbuff.h> //for skb structs and associated functions
#include <linux/spinlock.h> //we can't use any other mechanism since we will be locking at interrupt time mostly.
#include <linux/interrupt.h> //for using tasklets as a bottom-half mechanism

MODULE_LICENSE("GPL");

//TODO: change all unsigned chars to __u8, ints to appropriate kernel types

//TODO: code includes lots of hex addresses concerning various data locations in an ARP packet
//TODO: write defines so that code will be more readable

//ARP packet offsets
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
//make the whole packet look like it is coming from targetMAC

//incoming packet queue element
struct skb_list_node {
    struct sk_buff *skb;
    int processed;
    struct list_head node;
};

struct net_device *fakedev = 0;
struct net_device_ops fakedev_ndo;
struct fake_priv {
    struct napi_struct napi; //napi_struct is held in priv

    struct skb_list_node incoming_queue; //incoming skb queue 
    spinlock_t incoming_queue_protector; //incoming queue protector between rx interrupt handler and tasklet
    struct skb_list_node outgoing_queue; //outgoing skb queue
    spinlock_t outgoing_queue_protector; //outgoing queue protector between tasklet and NAPI poller
    //TODO: don't forget to free the dynamically allocated list elements
};

void fakeARP(unsigned long noparam);
DECLARE_TASKLET(forge_fake_reply, fakeARP, 0);  //we'll forge fake ARP replies in this tasklet

//int (*ndo_open)(struct net_device *dev) hook
int fakeARP_open(struct net_device *dev) {
    struct fake_priv *tmp_priv = netdev_priv(dev);
    printk(KERN_ALERT "setting fake arp device up!\n");

    napi_enable(&(tmp_priv->napi));
    printk(KERN_ALERT "napi enabled\n");

    return 0;
}

//int (*ndo_stop)(struct net_device *dev) hook
int fakeARP_stop(struct net_device *dev) {
    struct fake_priv *tmp_priv = netdev_priv(dev);
    napi_disable(&(tmp_priv->napi));
    printk(KERN_ALERT "napi disabled\n");
    printk(KERN_ALERT "shutting fake arp device down\n");

    //TODO: may be we should also flush the queues here?

    return 0;
}

//our napi poller function, without this we can't have kernel take packets from us
//int (*poll)(struct napi_struct *, int) hook
int fakeARP_poll(struct napi_struct *napi, int budget) {

    struct fake_priv *tmp_priv = netdev_priv(fakedev);

    int ret;
    int poll_ret = 0; //return 0 if all packets are transferred

    struct skb_list_node *outgoing_skb;
    struct skb_list_node *next_skb; //for safe list traversal

    //TODO: traverse the list of outgoing nodes, giving unprocessed ones to the kernel
    //TODO: then lock the list and delete processed nodes
    //TODO: DON'T DELETE the skbs inside the nodes, they belong to kernel once they are processed by NAPI.
    //TODO: not sure napi_gro_receive is the correct function here. consult kernel flow and Rami's .pdf file

    //TODO: we must not exceed the budget number of packets. how can we even give more than one packet at a time?

    spin_lock(&tmp_priv->outgoing_queue_protector);

    //TODO: we should traverse the list ourselves, so that we don't exceed the budget
    list_for_each_entry_safe(outgoing_skb, next_skb, &tmp_priv->outgoing_queue.node, node)
    {
        if(budget > 0)
        {
            if(outgoing_skb->skb != NULL) //don't delete the starting node, we use it to access the queue!
            {
                printk(KERN_ALERT "here is the fake ARP reply I'll feed to NAPI :\n");
                print_hex_dump_bytes(":", 1, outgoing_skb->skb->data, outgoing_skb->skb->len);

                ret = netif_receive_skb(outgoing_skb->skb);    //give the fake ARP reply to kernel

                if(ret==NET_RX_SUCCESS) {
                    printk(KERN_ALERT "fake arp reply skb fed to NAPI\n");
    
                    fakedev->stats.rx_packets++;
                    fakedev->stats.rx_bytes += outgoing_skb->skb->len;

                    budget--;

                    //just delete the node, don't delete the skb!
                    list_del(&outgoing_skb->node);
                }
            }
        }
        else
        {
            poll_ret = 1;
        }
    }

    spin_unlock(&tmp_priv->outgoing_queue_protector);

    napi_complete(&tmp_priv->napi); //we don't have any more packets to give you

    if(poll_ret) napi_schedule(&tmp_priv->napi); //we still have packets to give

    return poll_ret;
}

//our forging function called by the tasklet
void fakeARP(unsigned long noparam) {

    //TODO: take pending ARP requests from a list

    //we will be creating an ARP packet from bits
    __u8 *orgdata; //ARP request packet given to us to send over the cable
    __u8 *data;    //ARP reply packet we are going to forge and pretend it came from another host

    struct fake_priv *tmp_priv = netdev_priv(fakedev); //we'll use this only to schedule NAPI polling

    struct skb_list_node *outgoing_skb_node;
    struct skb_list_node *incoming_skb_node;
    struct skb_list_node *next_skb; //for safe list traversal

    spin_lock(&tmp_priv->incoming_queue_protector);
    
    //process the list of arp requests
    list_for_each_entry_safe(incoming_skb_node, next_skb, &tmp_priv->incoming_queue.node, node)
    {
        if(incoming_skb_node->skb != NULL)
        {
	    struct sk_buff *fake_skb = alloc_skb(42, GFP_KERNEL); //allocate a new skb for fake ARP response
	    if(fake_skb==NULL) {
	    	printk(KERN_ALERT "unable to allocate new skb for the fake ARP packet\n");
		break;
	    }
	    skb_put(fake_skb, 42); //create enough data section for fake ARP packet
	    memset(fake_skb, 0, 42); //zero it out

            orgdata = incoming_skb_node->skb->data; //original data section in the ARP request

            printk(KERN_ALERT "beginning to forge fake ARP reply\n");
            data = fake_skb->data;
        
            //we'll fill data part with a valid ARP reply using the info in the ARP request
            //copy all data section first, then swap and change necessary fields
            memcpy(data, orgdata, 42);
            //TODO: We will hold our own fake ARP table in later version
            memcpy(data, orgdata+ethersrc, 6); //copy src mac to dest mac field
            memset(data+ethersrc, 0xcc, 6); //for now all IP owners claim their mac is cc:cc:cc:cc:cc:cc
            *(data+ARPopts+7) = 0x02; //ARP replies have last octet of opts = 2
            memset(data+senderMAC, 0xcc, 6); //again fake IP owner mac
            memcpy(data+senderIP, orgdata+targetIP, 4); //copy asked IP addr to sender field
            memcpy(data+targetMAC, orgdata+senderMAC, 6); //copy sender MAC to target MAC
            memcpy(data+targetIP, orgdata+senderIP, 4); //copy sender IP to target IP

            //that's it, let's see our forged packet
            printk(KERN_ALERT "here is the fake ARP reply I forged:\n");
            print_hex_dump_bytes(":", 1, fake_skb->data, fake_skb->len);

            //add fake_skb to outgoing queue
            outgoing_skb_node = (struct skb_list_node*) kmalloc(sizeof(struct skb_list_node), GFP_KERNEL); //TODO: what if allocation fails here?
            outgoing_skb_node->skb = fake_skb;
            printk(KERN_ALERT "new fake skb is ready to give\n");

            //TODO: eth_type_trans can be moved to NAPI poller may be, I'm not sure.
            outgoing_skb_node->skb->protocol = eth_type_trans(outgoing_skb_node->skb, fakedev);
            __net_timestamp(outgoing_skb_node->skb); //as if we just got it fresh, without a timestamp
            //we need to call this before handing the packet over to kernel, 
            //it fixes head, data, mac etc. fields in the skb so that it seems like an ethernet packet
            
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

    printk(KERN_ALERT "napi scheduled, waiting for poller to take the fake ARP reply\n");

    return;   //success
}

//netdev_tx_t (*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev) hook
//enum netdev_tx_t is defined in netdevice.h
netdev_tx_t fakeARP_tx(struct sk_buff *skb, struct net_device *dev) {
    __u8 *data;
    int len;
    struct fake_priv *tmp_priv = netdev_priv(fakedev);
    struct skb_list_node *incoming_skb_node;

    len = skb->len;
    data = skb->data;

    //let's see what they want us to send (for debug)
    printk(KERN_ALERT "I have received a packet:\n");
    print_hex_dump_bytes(":", 1, skb->data, skb->len);

    //check if the packet is an ARP packet
    if(data[isitARP]==0x08 && data[isitARP+1]==0x06) { //2 octet long ethernet packet type part. 0x0806 is ARP
        //check if it is an ARP request
        if(data[ARPopts+6]==0x00 && data[ARPopts+7]==0x01) { //opcode 0x0001 is request, 0x0002 is reply

            //try to add skb to the list
            if(spin_trylock(&tmp_priv->incoming_queue_protector)) {

                struct sk_buff *incoming_skb = skb_clone(skb, GFP_ATOMIC);
                if(!incoming_skb) {
    	    	printk(KERN_ALERT "failed to clone skb for forging\n");
                    spin_unlock(&tmp_priv->incoming_queue_protector);
                    dev->stats.tx_dropped++;
                    return NETDEV_TX_LOCKED; //if cloning fails drop the packet
                }

                incoming_skb_node = kmalloc(sizeof(struct skb_list_node), GFP_ATOMIC);
                incoming_skb_node->skb = incoming_skb;
                incoming_skb_node->processed = 0;

                list_add(&incoming_skb_node->node, &(tmp_priv->incoming_queue.node));
                spin_unlock(&tmp_priv->incoming_queue_protector);

                //forger tasklet will take care of the rest
    	        tasklet_schedule(&forge_fake_reply);
            }

            else {
                //queue is being used by the tasklet or another interrupt
                dev->stats.tx_dropped++;
                return NETDEV_TX_LOCKED;
            }
        }
    }

    //normally this is done in a per CPU manner
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    //TODO: It appears freeing skb is not our responsibility. But I'm not sure :/

    return NETDEV_TX_OK;
}

void fakeARP_exit_module(void) {
    if(fakedev) {

    //TODO: cancel all the interrupts
    //TODO: unregister all the tasklets
    //TODO: then unregister the device
    //TODO: also rewrite device free function so that all dynamically allocated list elements are freed

        unregister_netdev(fakedev); //also free's device and priv parts since we set fakedev->destructor to free_dev
	
    }
    return;
}

int fakeARP_init_module(void) {
    int ret = 0;

    struct fake_priv *tmp_priv; //after registering the device we'll access private section with this
    fakedev = alloc_etherdev(sizeof(struct fake_priv));
    //just like alloc_dev but uses ether_setup to adjust a few ethernet related fields afterwards
    if(fakedev==NULL || fakedev == 0) {
        printk(KERN_ALERT "unable to allocate mem for fake ARP driver\n");
        return -ENOMEM;
    }
    printk(KERN_ALERT "fakeARP driver struct allocated at addr: %p\n", fakedev);
    printk(KERN_ALERT "its flags are set as %d by alloc_etherdev\n", fakedev->flags);

    //let's do the necessary adjustments
    fakedev->destructor = free_netdev; //called by unregister_device func. frees mem after unregistering
    fakedev_ndo.ndo_start_xmit = &fakeARP_tx;   //function to transmit packets to the other side of the cable
    fakedev_ndo.ndo_open = &fakeARP_open; //function used to "up" the device, ie. when user types ifconfig fkdev0 up
    fakedev_ndo.ndo_stop = &fakeARP_stop; //function used to "down" the device, ie. when user types ifconfig fkdev0 down
    fakedev->netdev_ops = &fakedev_ndo;
    memcpy(fakedev->dev_addr, "\0AAAAAA", ETH_ALEN);
    strncpy(fakedev->name, "fkdev%d", IFNAMSIZ);
    //fakedev->num_rx_queues = 1; //we don't need these, alloc etherdev already set it to 1 queue
    //fakedev->num_tx_queues = 1;

    tmp_priv = netdev_priv(fakedev); //now that we allocated the space, we can access our private section

    //init incoming packet queues and queue protectors, as many as current cpu count
    tmp_priv->incoming_queue.skb = NULL;
    tmp_priv->incoming_queue.processed = -1; //queue head will never be processed
    INIT_LIST_HEAD(&tmp_priv->incoming_queue.node);

    tmp_priv->outgoing_queue.skb = NULL;
    tmp_priv->outgoing_queue.processed = -1;
    INIT_LIST_HEAD(&tmp_priv->outgoing_queue.node);

    spin_lock_init(&tmp_priv->incoming_queue_protector);
    spin_lock_init(&tmp_priv->outgoing_queue_protector);

    //everything is set, register the device
    ret = register_netdev(fakedev);

    if(ret) {
        printk(KERN_ALERT "unable to register device. error code: %d\n", ret);
        return ret;
    }

    //add the device to NAPI system
    netif_napi_add(fakedev, &(tmp_priv->napi), fakeARP_poll, 1024); //16 is weight used for 10M eth

    return ret;

}

module_init(fakeARP_init_module);
module_exit(fakeARP_exit_module);

