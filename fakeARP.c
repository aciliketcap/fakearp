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
 *
 * Most of these are different in the master branch. The comments and code structure is
 * arranged to make it understandable as a tutorial. Please read master or devel branch
 * if you want to read actual code.
 */

#include <linux/module.h> //for init/exit macros
#include <linux/kernel.h> //for printk and other stuff
#include <linux/netdevice.h> //almost every struct, mainly net_device and associated functions
#include <linux/etherdevice.h> //alloc_etherdev
#include <linux/skbuff.h> //for skb structs and associated functions

MODULE_LICENSE("GPL");

struct net_device *fakedev = 0;
struct net_device_ops fakedev_ndo;
struct fake_priv {
	struct napi_struct napi;	//napi_struct is held in priv
	struct sk_buff *fakeskb;	//fake packet buffer
	struct sk_buff *fakeskb_copy;	//the copy we give to napi
	int packet_ready;		//1 if we have a packet to give to NAPI, 0 otherwise

	//we'll be forging one packet at a time
	//if another ARP request comes in while we were working on an ARP reply packet
	//it won't be processed and it will be dropped, they'll send a new one anyway
};

//int (*ndo_open)(struct net_device *dev) hook
int fakeARP_open(struct net_device *dev) {
	struct fake_priv *tmp_priv = netdev_priv(dev);
	printk(KERN_ALERT "setting fake arp device up!\n");

	napi_enable(&(tmp_priv->napi));
	printk(KERN_ALERT "napi enabled for rx\n");

        netif_start_queue(dev);
	printk(KERN_ALERT "tx enabled\n");

	return 0;
}

//int (*ndo_stop)(struct net_device *dev) hook
int fakeARP_stop(struct net_device *dev) {
	struct fake_priv *tmp_priv = netdev_priv(dev);

	napi_disable(&(tmp_priv->napi));
	printk(KERN_ALERT "napi disabled\n");

        netif_start_queue(dev);
	printk(KERN_ALERT "tx disabled\n");

	printk(KERN_ALERT "shutting fake arp device down\n");

	return 0;
}

//our napi poller function, without this we can't have kernel take packets from us
//int (*poll)(struct napi_struct *, int) hook
int fakeARP_poll(struct napi_struct *napi, int budget) {
	//no matter what budget is I always have just one packet :/

	struct fake_priv *tmp_priv = netdev_priv(fakedev);
	int ret;

	if(!tmp_priv->packet_ready) {
		return 0;
	}

	ret = netif_receive_skb(tmp_priv->fakeskb_copy); //give the fake ARP reply to kernel

	if(ret) {
		printk(KERN_ALERT "fake arp skb fed to NAPI\n");
		fakedev->stats.rx_packets++;
		fakedev->stats.rx_bytes += tmp_priv->fakeskb->len;
	}

	napi_complete(&(tmp_priv->napi)); //we don't have any more packets to give you NAPI
	tmp_priv->packet_ready = 0; //we gave our packet, wait for next one

	netif_wake_queue(fakedev); //tell kernel we can take more packets to transmit

	return ret;
}

//our forging function. Takes an ARP request broadcast packet and creates a suitable ARP response packet
int fakeARP(struct sk_buff *skb) {
	//we will be creating an ARP packet from bits
	unsigned char *orgdata; //ARP request packet given to us to send over the cable
	unsigned char *data;    //ARP reply packet we are going to forge and pretend it came from another host
	unsigned char *ethersrc; //src in ethernet header
	unsigned char *etherdst; //dst in ethernet header
	unsigned char *isitARP; //ARP protocol identifier
	unsigned char *ARPopts; //ARP protocol config
	unsigned char *senderIP; //ARP replier IP (written in ARP request)
	unsigned char *senderMAC; //ARP replier MAC (fake)
	unsigned char *targetIP; //IP of the host who created the ARP request
	unsigned char *targetMAC; //MAC of the host who created the ARP request

	struct fake_priv *tmp_priv = netdev_priv(fakedev); //we'll use this only to schedule NAPI polling

	orgdata = skb->data; //original data section in the ARP request

	printk(KERN_ALERT "beginning to forge fake ARP reply\n");
	data = tmp_priv->fakeskb->data;
	//we'll fill data part with a valid ARP reply using the info in the ARP request
	etherdst = data;
	ethersrc = data+6;
	isitARP = data+12; //2 bytes, should be 0x0806 if this is an ARP packet
	ARPopts = data+14; //8 byte long fixed ARP opts
	senderMAC = data+22;
	senderIP = data+28;
	targetMAC = data+32; //zeroed in src pkt
	targetIP = data+38; //total: 42 bytes
	//I used different pointers for each part since this code is meant for training purposes
	//we could have copied the whole data from the ARP request and do some bit juggling
	//but that looks rather obscure

	memcpy(etherdst, orgdata + 6, 6);
	memset(ethersrc, 0xcc, 6); //IP owner has mac cc:cc:cc:cc:cc:cc
	//MAC is static in tutorial code
	memcpy(isitARP, orgdata+12, 2);
	memcpy(ARPopts, orgdata+14, 8);
	ARPopts[7] = 0x02; //arp reply has last bit of opts 2 instead of 1
	memset(senderMAC, 0xcc, 6); //again fake IP owner mac
	memcpy(senderIP, orgdata+38, 4); //copy the asked address to sender field
	memcpy(targetMAC, orgdata+22, 6); //copy sender MAC to target MAC
	memcpy(targetIP, orgdata+28, 4); //copy sender IP to target IP

	//that's it, let's see our forged packet
	printk(KERN_ALERT "here is the fake ARP reply I forged:\n");
	print_hex_dump(KERN_ALERT, ":", 1, 16, 1, tmp_priv->fakeskb->data, tmp_priv->fakeskb->len, true); //print_hex_dump_bytes modified

	tmp_priv->fakeskb_copy = skb_copy(tmp_priv->fakeskb, GFP_ATOMIC);
	printk(KERN_ALERT "skb cloned\n");
	tmp_priv->fakeskb_copy->protocol = eth_type_trans(tmp_priv->fakeskb_copy, fakedev);
	//we need to call eth_type_trans before handing the packet over,
	//it sets ethernet header ptr, decides packet type (which is what to do with the packet actually)
	//and returns the ethernet protocol (I was surprised to learn there are more than one, too)

	tmp_priv->packet_ready = 1;

	napi_schedule(&(tmp_priv->napi)); //tell napi system we have received packets and it should poll our device some time.
	printk(KERN_ALERT "napi scheduled, waiting for poller to take the fake ARP reply\n");

	return 1; 	//success
}

//netdev_tx_t (*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev) hook
//enum netdev_tx_t is defined in netdevice.h
netdev_tx_t fakeARP_tx(struct sk_buff *skb, struct net_device *dev) {
	char *data;
	int len;
	struct fake_priv *tmp_priv = netdev_priv(fakedev);

	len = skb->len;
	data = skb->data;

	//let's see what they want us to send
	printk(KERN_ALERT "I have received a packet of length %d:\n", skb->len);
	print_hex_dump(KERN_ALERT, ":", 1, 16, 1, skb->data, skb->len, true); //print_hex_dump_bytes modified

	if(tmp_priv->packet_ready) {
		printk(KERN_ALERT "we are waiting for kernel to take our previous ARP reply right now, give the packet back\n");
		netif_stop_queue(dev);
		return NETDEV_TX_BUSY; //tell the kernel we could not process the packet and it should resend it sometime later.
	}

	//check if the packet is an ARP request packet
	if(data[12]==0x08 && data[13]==0x06) { //after 12 octets of MAC addrs comes the 2 octet long type part. 0x0806 is ARP
		if(data[20]==0x00 && data[21]==0x01) { //opcode 0x0001 is request, 0x0002 is reply

			netif_stop_queue(dev); //tell kernel we won't be able to take new packets, we can forge only one at a time

			if(!fakeARP(skb)) {
				printk(KERN_ALERT "fake arp reply could not be forged because of some error\n"); //no error case in tutorial
				dev_kfree_skb_any(skb); //free the original packet (will be freed in next net_tx_action if we are in irq context)
				netif_wake_queue(dev);
				return NETDEV_TX_OK; //normally we should return NETDEV_TX_BUSY here since tx failed
				//but who cares, if it is really important they'll send another one
			}
		}
	}

	//normally stats are gathered in a per-CPU manner, but we can already use at most one CPU
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	//if the packet is not an ARP request we are not interested in it
	dev_kfree_skb_any(skb); //oops, we dropped it :D
	//we'll still tell them we sent it over the cable though
	//we used dev_kfree_skb_any because this function may run on int time or syscall time

	return NETDEV_TX_OK;
}

void fakeARP_exit_module(void) {
	if(fakedev) {
		unregister_netdev(fakedev); //also free's net_device and priv parts since we set fakedev->destructor to free_netdev
	}
	return;
}

int fakeARP_init_module(void) {

	int ret;
	struct fake_priv *tmp_priv; //after registering the device we'll access private section with this

	fakedev = alloc_etherdev(sizeof(struct fake_priv)); //just like alloc_dev but uses ether_setup afterwards

	if(fakedev==NULL || fakedev == 0) {
		printk(KERN_ALERT "unable to allocate mem for fake ARP driver\n");
		return -ENOMEM;
	}
	printk(KERN_ALERT "fakeARP driver struct allocated at addr: %p\n", fakedev);
	printk(KERN_ALERT "its flags are set as %d by alloc_etherdev\n", fakedev->flags);

	//let's do the necessary adjustments
	fakedev->destructor = free_netdev;		//called by unregister_device func. frees mem after unregistering
	fakedev_ndo.ndo_start_xmit = &fakeARP_tx;	//function to transmit packets to the other side of the cable
	fakedev_ndo.ndo_open = &fakeARP_open;		//function used to "up" the device, ie. when user types ifconfig fkdev0 up
	fakedev_ndo.ndo_stop = &fakeARP_stop;		//function used to "down" the device, ie. when user types ifconfig fkdev0 down
	fakedev->netdev_ops = &fakedev_ndo;
	memcpy(fakedev->dev_addr, "\0AAAAAA", ETH_ALEN); //set device MAC to AA:AA:AA:00:00:00
	strncpy(fakedev->name, "fkdev%d", IFNAMSIZ);	//change device name fkdev0

	tmp_priv = netdev_priv(fakedev); //now that we allocated the space, we can access our private section

	tmp_priv->fakeskb = alloc_skb(42, GFP_KERNEL); //allocate the empty skb we'll arrange as our fake reply

	if(tmp_priv->fakeskb==NULL) {
		printk(KERN_ALERT "unable to allocate new skb for fake ARP packet\n");
		return -ENOMEM; //if allocation is not successful return
	}

	skb_put(tmp_priv->fakeskb, 42);  //42 bytes is the length of an ARP packet, reserving space for ARP packet
	memset(tmp_priv->fakeskb->data, 0, 42); //zero it out
	tmp_priv->packet_ready = 0;

	//register the device to NAPI system for receive polling
	netif_napi_add(fakedev, &(tmp_priv->napi), &fakeARP_poll, 16); //16 is weight used for 10M eth

	//everything is set, register the device
	ret = register_netdev(fakedev);

	if(ret) {
		printk(KERN_ALERT "unable to register device. error code: %d\n", ret);
		return ret;
	}

	return ret;
}

module_init(fakeARP_init_module);
module_exit(fakeARP_exit_module);
