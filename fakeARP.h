#include <linux/proc_fs.h> //to interact with userspace using procfs
#include <linux/seq_file.h> //print output using procfs
#include <linux/kernel.h> //for printk and other stuff
#include <linux/slab.h> //kmalloc and kfree
#include <linux/spinlock.h> //we can't use any other mechanism since we will be locking at interrupt time mostly.
#include <linux/percpu.h> //per-cpu variables for holding stats
#include <linux/u64_stats_sync.h> //to sync 64bit per-cpu variables on 32bit archs

//extra debugging which just dumps lots of lines to show how stuff works
//I'd make this config option if I wasn't compiling in my own directory
//#define FAKEARP_EXTRA_DEBUG
#define debug_hex_dump(obj,len)	print_hex_dump(KERN_DEBUG, ":", 1, 16, 1, obj, len, true);

#ifdef FAKEARP_EXTRA_DEBUG
struct rtnl_link_stats64 *fakeARP_get_stats64_extra_debug(struct net_device *dev, struct rtnl_link_stats64 *total_stats);
#endif

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

#define FIRST_MAC 0xCCCCCCCCCC00

#define FAKEARP_HASH_SIZE 256
//TODO: implement locking for this global (for now incoming lock is enough)
//TODO: I don't need to zero these out, they are already in BSS, right?
//very simple hash table implementation
extern struct hlist_head fake_mac_list[FAKEARP_HASH_SIZE];
extern spinlock_t fake_mac_list_protector;

//TODO: what data type kernel uses for IP and MAC internally?
//I used byte arrays since I will be copying from buffers
struct ip_mac_pair {
	u8 ip[4];
	u8 mac[6];
	struct hlist_node mac_list;
};

struct hlist_head *hash_fake_mac_list(u8 *ip);
u8 *insert_ip_mac_pair(u8 *ip, u8 *mac);
u8 *insert_new_ip_mac_pair(u8 *ip);
//TODO: put remove function signature here
u8 *get_mac(u8 *ip);
void dump_ip_list(void);

//proc entry to dump IP - MAC pairs
//TODO: this proc entry's functionality will be trasferred to sysfs later
struct proc_dir_entry* create_fakearp_dump_entry(void);

void *start_fakearp_dump(struct seq_file *file, loff_t *pos);
void *next_fakearp_dump(struct seq_file *file, void *cur_it, loff_t *pos);
void stop_fakearp_dump(struct seq_file *file, void *cur_it);
int show_fakearp_dump(struct seq_file *file, void *cur_it);

int show_fakearp_dump_entry(struct seq_file *file, void *seq);
int open_fakearp_dump_entry(struct inode *inode, struct file *file);
int close_fakearp_dump_entry(struct inode *inode, struct file *file);
