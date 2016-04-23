#include "fakeARP.h"
#include <linux/percpu.h> //per-cpu variables for holding stats
#include <linux/u64_stats_sync.h> //to sync 64bit per-cpu variables on 32bit archs
#include <linux/netdevice.h> //almost every struct, mainly net_device and associated functions

#ifdef FAKEARP_EXTRA_DEBUG
struct rtnl_link_stats64 *fakeARP_get_stats64_extra_debug(struct net_device *dev, struct rtnl_link_stats64 *total_stats)
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


#endif
