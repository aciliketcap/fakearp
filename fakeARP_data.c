#include "fakeARP.h"

#define FAKEARP_HASH_SIZE 256
//TODO: use hlist in hash instead of list, it's half the price in memory :)
struct list_head fake_mac_list[FAKEARP_HASH_SIZE];

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

//use a proc entry to dump hash table entries
void *start_fakearp_dump(struct seq_file *file, loff_t *pos)
{
	//alloc iterator
	if(*pos < FAKEARP_HASH_SIZE) {
		loff_t *spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
		if (!spos)
			return NULL;
		//assign initial pos
		*spos = *pos;
		return spos;
	} else
		return NULL;
}

void *next_fakearp_dump(struct seq_file *file, void *cur_it, loff_t *pos)
{
	loff_t *spos = cur_it;

	if(*spos < FAKEARP_HASH_SIZE) {
		*pos = ++*spos;
		return spos;
	} else
		return NULL;
}

void stop_fakearp_dump(struct seq_file *file, void *cur_it) {
	kfree(cur_it);
}

int show_fakearp_dump(struct seq_file *file, void *cur_it) {
	struct ip_mac_pair *tmp;

	//TODO: I don't understand why assign instead of casting, again.
	loff_t *it = cur_it;

	if(*it == FAKEARP_HASH_SIZE) {
		seq_printf(file, "End of hash\n");
		return 0;
	}

	if(list_empty(&fake_mac_list[*it]))
		return SEQ_SKIP; //only print filled hashes
	else {
		seq_printf(file, "List of IPs in hash %lld\n", *it);
		list_for_each_entry(tmp, &fake_mac_list[*it], mac_list) {
			seq_printf(file, "IP %pI4 has mac %pM\n", tmp->ip, tmp->mac);
			//TODO: seq_printf understands IP and mac format, right?
			//TODO: guess not :(
			//printk(KERN_DEBUG "IP %pI4 has mac %pM\n", tmp->ip, tmp->mac);
		}
	}

	return 0;
}

const struct seq_operations fakearp_dump_seq_ops = {
	.start = start_fakearp_dump,
	.next = next_fakearp_dump,
	.stop = stop_fakearp_dump,
	.show = show_fakearp_dump
};

//use seq open and iterate through hash table
int open_fakearp_dump_entry(struct inode *inode, struct file *file)
{
	//TODO: may be I need to protect the list from now on...
	return seq_open(file, &fakearp_dump_seq_ops);
}

const struct file_operations fakearp_dump_entry_fops = {
	.owner = THIS_MODULE,
	.open = open_fakearp_dump_entry,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

//TODO: I don't think we need this either, just go with proc_create or something
struct proc_dir_entry* create_fakearp_dump_entry()
{
	struct proc_dir_entry *new_fakearp_dump_entry;

	new_fakearp_dump_entry = proc_create("fakearp_dump", 0, NULL, &fakearp_dump_entry_fops);
	if(!new_fakearp_dump_entry)
	{
		printk(KERN_ALERT "Unable to create a proc entry to dump IP-MAC list of fakearp");
	}

	return new_fakearp_dump_entry;
}
