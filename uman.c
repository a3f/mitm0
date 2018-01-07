/*
 * uman.c  --  the network driver micro-manager
 * Copyright (C) 2017 Ahmad Fatoum
 *
 * Example (micromanage eth1 through uman0):
 *   ip link add uman0 type bond
 *   ip link set eth1 master uman0
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/debugfs.h>
#include <linux/rtnetlink.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/skbuff.h>

#define DRV_VERSION        "0.01"
#define DRV_RELDATE        "2017-01-01"
#define DRV_NAME        "uman"
#define DRV_DESCRIPTION        "Network driver micro-manager"

int verbose = 1; /* FIXME wasn't there a more idiomatic way? */
/* I think /usr/src/linux/Documentation/dynamic-debug-howto.txt */
module_param(verbose, int, 0);
MODULE_PARM_DESC(verbose, "0 != 1, 1 = narrate every function call");

#define VERBOSE_LOG(...) do{ if (verbose) printk(DRV_NAME ": " __VA_ARGS__);} \
				while (0)
#define VERBOSE_LOG_FUNENTRY() VERBOSE_LOG("%s()", __func__)


/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct uman {
	struct net_device *dev;
	spinlock_t lock;

	struct slave {
		struct net_device *dev;
	} slave;
};

#define uman_slave_list(uman) (&(uman)->dev->adj_list.lower)
#define uman_has_slave(uman) !list_empty(uman_slave_list(uman))
#define uman_slave(uman) (uman_has_slave(uman) ? \
	netdev_adjacent_get_private(uman_slave_list(uman)->next) : NULL)
#define uman_of(slaveptr) container_of((slaveptr), struct uman, slave)


/*
 * Open and close
 */
int uman_open(struct net_device *dev)
{
	VERBOSE_LOG_FUNENTRY();
	/* Neither bond not team call netif_(start|stop)_queue. why? */
	/* netif_start_queue(dev); */
	return 0;
}

int uman_stop(struct net_device *dev)
{
	VERBOSE_LOG_FUNENTRY();
	/* netif_stop_queue(dev); */
	return 0;
}

/*
 * Transmit a packet (called by the kernel)
 */
int uman_start_xmit(struct sk_buff *skb, struct net_device *uman_dev)
{
	VERBOSE_LOG_FUNENTRY();
	kfree_skb(skb);
	return 0;
}

static const struct net_device_ops uman_netdev_ops = {
	.ndo_open		= uman_open,
	.ndo_stop		= uman_stop,
	.ndo_start_xmit		= uman_start_xmit,
};

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void uman_setup(struct net_device *uman_dev)
{
	struct uman *uman = netdev_priv(uman_dev);
	VERBOSE_LOG_FUNENTRY();

	spin_lock_init(&uman->lock);
	uman->dev = uman_dev;
	uman->slave.dev = NULL;

	ether_setup(uman_dev); /* assign some of the fields */

	uman_dev->netdev_ops = &uman_netdev_ops;
	uman_dev->destructor = free_netdev;
}

/*--------------------------------- DebugFS ---------------------------------*/
static struct dentry *debugfs_dir;
static ssize_t debugfs_get_slave(struct file *file, char __user *buff,
	size_t count, loff_t *offset)
{
    struct net_device *uman_dev = file->f_inode->i_private;
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    if (!debugfs_dir)
        return -EIO;

    if (!slave)
        return -EAGAIN;

    return simple_read_from_buffer(buff, count, offset, slave->dev->name,
	    strlen(slave->dev->name));
}
static ssize_t debugfs_set_slave(struct file *file, const char __user *buff,
size_t count, loff_t *offset)
{
    struct net_device *uman_dev = file->f_inode->i_private;
    struct net_device *slave_dev;
    char ifname[IFNAMSIZ+1];
    ssize_t ret, nulpos;
    int result;
    VERBOSE_LOG_FUNENTRY();

    if (!debugfs_dir)
        return -EIO;

    ret = simple_write_to_buffer(ifname, sizeof ifname-1, offset, buff, count);
    if (ret <= 0)
        return ret;

    nulpos = ret;
    if (ifname[ret-1] == '\n')
        nulpos--;

    ifname[nulpos] = '\0';

    rtnl_lock();

    slave_dev = __dev_get_by_name(&init_net, ifname);

    if (!slave_dev)
        return -EINVAL;

    printk(DRV_NAME ": (%p) You want to enslave %s@%p (%s)?\n", uman_dev,
	    ifname, slave_dev, slave_dev->name);

#if 0
    if ((result = uman_enslave(uman_dev, slave_dev)))
        ret = result;
#endif

    rtnl_unlock();

    return ret;
}
static const struct file_operations slave_fops = {
    .owner = THIS_MODULE,
    .read  = debugfs_get_slave,
    .write = debugfs_set_slave,
};

/*---------------------------- Module init/fini -----------------------------*/
static struct net_device *uman_dev;

int __init uman_init_module(void)
{
	int ret;
	VERBOSE_LOG_FUNENTRY();

	/* Allocate the devices */
	uman_dev = alloc_netdev(sizeof(struct uman), "uman%d",
		NET_NAME_UNKNOWN, uman_setup);
	if (!uman_dev)
		return -ENOMEM;

	if ((ret = register_netdev(uman_dev))) {
		printk(DRV_NAME ": error %i registering device \"%s\"\n",
				ret, uman_dev->name);
		unregister_netdev(uman_dev);
		return -ENODEV;
	}

	debugfs_dir = debugfs_create_dir(uman_dev->name, NULL);
	if (IS_ERR_OR_NULL(debugfs_dir)) {
		printk(KERN_ALERT DRV_NAME ": failed to create /sys/kernel/debug/%s\n",
            uman_dev->name);
		debugfs_dir = NULL;
	} else {
		struct dentry *dentry = debugfs_create_file("slave", 0600, debugfs_dir,
            uman_dev, &slave_fops);
		if (IS_ERR_OR_NULL(dentry)) {
			printk(KERN_ALERT DRV_NAME ": failed to create /sys/kernel/debug/%s/slave\n",
            uman_dev->name);
		}
	}

	printk(DRV_NAME ": Initialized module with interface %s@%p\n", uman_dev->name, uman_dev);

	return 0;
}

void __exit uman_exit_module(void)
{
	VERBOSE_LOG_FUNENTRY();
	unregister_netdev(uman_dev);
	printk(DRV_NAME ": Exiting module\n");
}

module_init(uman_init_module);
module_exit(uman_exit_module);

MODULE_AUTHOR("Ahmad Fatoum");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_VERSION(DRV_VERSION);
