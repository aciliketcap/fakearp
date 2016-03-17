#include "fakeARP.h"

//TODO: may be I should make hash table per-device instead of global
//use hlist in hash instead of list and initial hash table will cost half the mem price
struct hlist_head fake_mac_list[FAKEARP_HASH_SIZE];
spinlock_t fake_mac_list_protector;

//hash function
struct hlist_head *hash_fake_mac_list(u8 *ip) {
	//hash it by the last byte of the IP address
	//no collision for LAN addresses like 192.168.1.x
	return &fake_mac_list[*(ip+3)];
}

//this will be used in bottom half tasklet
//TODO: check for existing entries before adding new
u8 *insert_ip_mac_pair(u8 *ip, u8 *mac) {
	struct ip_mac_pair *new_pair = kmalloc(sizeof(struct ip_mac_pair), GFP_KERNEL);
	if(!new_pair)
		return 0;

	memcpy(new_pair->ip, ip, 4);
	memcpy(new_pair->mac, mac, 6);

	spin_lock(&fake_mac_list_protector);
	hlist_add_head(&new_pair->mac_list, hash_fake_mac_list(ip));
	spin_unlock(&fake_mac_list_protector);

	return new_pair->mac;
}

//for now let's start with CC:CC:CC:CC:CC:00 and increment every time we fake a new IP
static u64 next_mac = FIRST_MAC;

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

	spin_lock(&fake_mac_list_protector);
	if(hlist_empty(hash_fake_mac_list(ip))) {
		goto no_mac;
	} else {
		//compare full mac, loop until we find it or list is over
		hlist_for_each_entry(tmp, hash_fake_mac_list(ip), mac_list) {
#ifdef FAKEARP_EXTRA_DEBUG
			printk(KERN_DEBUG "looking at list ip %pI4 and new ip %pI4\n", tmp->ip, ip);
#endif

			if(memcmp(tmp->ip, ip, 4)) { //proceed to next one if cmp fails
				continue;
			} else {
				spin_unlock(&fake_mac_list_protector);
				return tmp->mac;
			}
		}
	}

no_mac:
	printk(KERN_DEBUG "No MAC recorded for IP %pI4 before\n", ip);
	spin_unlock(&fake_mac_list_protector);
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
		spin_lock(&fake_mac_list_protector); //lock here, unlock at stop
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
	spin_unlock(&fake_mac_list_protector);
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

	if(hlist_empty(&fake_mac_list[*it]))
		return SEQ_SKIP; //only print filled hashes
	else {
		seq_printf(file, "List of IPs in hash %lld\n", *it);
		hlist_for_each_entry(tmp, &fake_mac_list[*it], mac_list) {
			seq_printf(file, "IP %pI4 has mac %pM\n", tmp->ip, tmp->mac);
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

//convert string IP - MAC pair to bytes - kinda clumsy
//format x.x.x.x-aa:aa:aa:aa:aa:aa
int pair_str2bytes(char *str, u8 *ip, u8 *mac ) {
	int i, j;
	char num[4];

	for(i=0;i<4;i++) {
		j=0;

		while(*str <= '9' && *str >= '0' && j < 4)
			num[j++] = *str++;

		if(j==0) return -1;

		if(*str == '.') {
			num[j] = '\0';
			if(kstrtou8(num, 10, ip+i))
				return -1;
			str++;
			continue;
		}

		if(i == 3 && *str++ == '-') {
			num[j] = '\0';
			if(kstrtou8(num, 10, ip+i))
				return -1;
		} else
			return -1;
	 }

	for(i=0;i<6;i++) {
		j=0;

		num[0] = *str++;
		num[1] = *str++;
		num[2] = '\0';
		if(i<5 && *str != ':')
			return -1;

		if(kstrtou8(num, 16, mac+i))
			return -1;

		str++;
	}

	return 0;
}

//proc entry to add one IP-MAC pair
//
int open_fakearp_new_pair_entry(struct inode *inode, struct file *file)
{
	printk(KERN_DEBUG "inside open function\n");
	return 0;
}

ssize_t write_fakearp_new_pair_entry(struct file *file, const char *buffer, size_t count, loff_t *pos)
{
	char pair_str[FAKEARP_IPMAC_STRING_MAX_LEN];
	u8 ip[4];
	u8 mac[6];

	printk(KERN_DEBUG "inside write function\n");

	if(copy_from_user(pair_str, buffer, FAKEARP_IPMAC_STRING_MAX_LEN))
		return -EFAULT;

	printk(KERN_DEBUG "copied from user\n");

	if(pair_str2bytes(pair_str, ip, mac))
		return -EFAULT;

	printk(KERN_INFO "Adding ip: %pI4 mac: %pM to the list\n", ip, mac);

	insert_ip_mac_pair(ip,mac);

	return count;
}

const struct file_operations fakearp_new_pair_entry_fops = {
	.owner = THIS_MODULE,
	.open = open_fakearp_new_pair_entry,
	.write = write_fakearp_new_pair_entry
};
