#include "fakeARP.h"

//TODO: take page structure from ez8139 and enter mac - ip pairs from there and test this code

struct list_head fake_mac_list[256];

//hash function
struct list_head *hash_fake_mac_list(u8 *ip) {
	//hash it by the last byte of the IP address
	//no collision for LAN addresses like 192.168.1.x
	return &fake_mac_list[*(ip+3)];
}

//this will be used in bottom half tasklet
u8 *insert_ip_mac_pair(u8 *ip, u8 *mac) {
	struct ip_mac_pair *new_pair = kmalloc(sizeof(struct ip_mac_pair), GFP_KERNEL);
	if(!new_pair)
		return 0;

	memcpy(new_pair->ip, ip, 4);
	memcpy(new_pair->mac, mac, 6);

	list_add(&new_pair->mac_list, hash_fake_mac_list(ip));

	return new_pair->mac;
}

//for now let's start with CC:CC:CC:CC:CC:00 and increment every time we fake a new IP
static u64 next_mac = 0xCCCCCCCCCC00;

u8 *insert_new_ip_mac_pair(u8 *ip) {
	u64 n_next_mac = cpu_to_be64(next_mac);
	u8 *next_mac_ptr = ((u8*) &n_next_mac) + 2;
	u8 *ret;

	ret = insert_ip_mac_pair(ip, next_mac_ptr);
	next_mac++;

	return ret;
}

//TODO: we don't need a remove_ip_hash function for now, but it will be written eventually

//return pointer to mac address which is associated with ip
u8 *get_mac(u8 *ip) {
	struct ip_mac_pair *tmp;

	if(list_empty(hash_fake_mac_list(ip))) {
		printk(KERN_DEBUG "No MAC recorded for IP %pI4 before\n", ip);
		return 0;
	} else {
		//printk(KERN_DEBUG "loop da list %pI4\n", ip);
		//compare full mac, loop until we find it or list is over
		list_for_each_entry(tmp, hash_fake_mac_list(ip), mac_list) {
			printk(KERN_DEBUG "looking at list ip %pI4 and new ip %pI4\n", tmp->ip, ip);

			if(memcmp(tmp->ip, ip, 4)) { //proceed to next one if cmp fails
				continue;
			} else {
				return tmp->mac;
			}
		}
	}

	printk(KERN_DEBUG "No MAC recorded for IP %pI4 before\n", ip);

	return 0;
}

//for better debugging
void dump_ip_list(void) {
	struct ip_mac_pair *tmp;
	int i;

	for(i=0;i<256;i++) {
		if(list_empty(&fake_mac_list[i]))
			printk(KERN_NOTICE "hash %d is empty\n", i);
		else {
			printk(KERN_NOTICE "IPs in hash %d\n", i);
			list_for_each_entry(tmp, &fake_mac_list[i], mac_list) {
				printk(KERN_NOTICE "IP %pI4 has mac %pM\n", tmp->ip, tmp->mac);
			}
		}
	}

	return;
}
