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
#include <linux/if_arp.h>
#include <net/sch_generic.h>
#include <linux/etherdevice.h>
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

/*----------------------------------- Rx ------------------------------------*/

/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
static rx_handler_result_t uman_handle_frame(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    struct uman *uman;
    VERBOSE_LOG_FUNENTRY();

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (unlikely(!skb))
        return RX_HANDLER_CONSUMED;

    *pskb = skb;

    uman = rcu_dereference(skb->dev->rx_handler_data);

    skb->dev = uman->dev;

    return RX_HANDLER_ANOTHER; /* Do another round in receive path */
}


/*----------------------------------- Tx ------------------------------------*/

/**
 * uman_dev_queue_xmit - Prepare skb for xmit.
 *
 * @uman: uman device that got this skb for tx.
 * @skb: skb to transmit
 */
static inline int uman_dev_queue_xmit(struct slave *slave, struct sk_buff *skb)
{
    BUILD_BUG_ON(sizeof(skb->queue_mapping) !=
             sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
    skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);
    VERBOSE_LOG_FUNENTRY();

    skb->dev = slave->dev;

    return dev_queue_xmit(skb);
}

/*
 * Transmit a packet (called by the kernel)
 */
static netdev_tx_t uman_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    netdev_tx_t ret = NETDEV_TX_OK;
    struct uman *uman = netdev_priv(dev);
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    /* TODO rcu lock? */
    if (slave)
        ret = uman_dev_queue_xmit(slave, skb);
    else {
        atomic_long_inc(&dev->tx_dropped);
        dev_kfree_skb_any(skb);
    }


    return ret;
}

/*-------------------------- Bonding Notification ---------------------------*/

static int uman_master_upper_dev_link(struct uman *uman, struct slave *slave)
{
    int err;
    /* we aggregate everything into one link, so that's technically a broadcast */
    struct netdev_lag_upper_info lag_upper_info = {
        .tx_type = NETDEV_LAG_TX_TYPE_BROADCAST
    };
    VERBOSE_LOG_FUNENTRY();

    err = netdev_master_upper_dev_link(slave->dev, uman->dev, slave, &lag_upper_info);
    if (err)
        return err;
    rtmsg_ifinfo(RTM_NEWLINK, slave->dev, IFF_SLAVE, GFP_KERNEL);
    return 0;
}

static void uman_upper_dev_unlink(struct uman *uman, struct slave *slave)
{
    VERBOSE_LOG_FUNENTRY();
    netdev_upper_dev_unlink(slave->dev, uman->dev);
    slave->dev->flags &= ~IFF_SLAVE;
    rtmsg_ifinfo(RTM_NEWLINK, slave->dev, IFF_SLAVE, GFP_KERNEL);
}
/* FIXME unused */
#if 0
static void bond_lower_state_changed(struct slave *slave)
{
    struct netdev_lag_lower_state_info info;
    VERBOSE_LOG_FUNENTRY();

    info.link_up = slave->link_up;
    info.tx_enabled = slave->dev != NULL;
    netdev_lower_state_changed(slave->dev, &info);
}
#endif

/**
 * uman_set_dev_addr - clone slave's address to bond
 * @uman_dev: bond net device
 * @slave_dev: slave net device
 *
 * Should be called with RTNL held.
 */
static void uman_set_dev_addr(struct net_device *uman_dev, struct net_device *slave_dev)
{
    VERBOSE_LOG_FUNENTRY();
    netdev_dbg(uman_dev, "uman_dev=%p slave_dev=%p slave_dev->name=%s slave_dev->addr_len=%d\n",
           uman_dev, slave_dev, slave_dev->name, slave_dev->addr_len);
    memcpy(uman_dev->dev_addr, slave_dev->dev_addr, slave_dev->addr_len);
    uman_dev->addr_assign_type = NET_ADDR_STOLEN;
    call_netdevice_notifiers(NETDEV_CHANGEADDR, uman_dev);
}

/* Set the carrier state for the master according to the state of its
 * slaves.
 *
 * Returns zero if carrier state does not change, nonzero if it does.
 */
static int uman_set_carrier(struct uman *uman)
{
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    if (!slave)
        goto down;

    if (!netif_carrier_ok(uman->dev)) {
        netif_carrier_on(uman->dev);
        return 1;
    }

down:
    if (netif_carrier_ok(uman->dev)) {
        netif_carrier_off(uman->dev);
        return 1;
    }
    return 0;
}


/*--------------------------------- Slavery ---------------------------------*/

static int uman_enslave(struct net_device *uman_dev,
		struct net_device *slave_dev)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *new_slave = NULL;
    int res = 0;
    VERBOSE_LOG_FUNENTRY();

    /* We only micromanage one device */
    if (uman_has_slave(uman)) {
        netdev_err(uman_dev, "Error: uman can only have one slave\n");
        return -EBUSY;
    }

    /* already in-use? */
    if (netdev_is_rx_handler_busy(slave_dev)) {
        netdev_err(uman_dev, "Error: Device is in use and cannot be enslaved\n");
        return -EBUSY;
    }

    if (uman_dev == slave_dev) {
        netdev_err(uman_dev, "uman cannot enslave itself.\n");
        return -EPERM;
    }

    if (slave_dev->type != ARPHRD_ETHER) {
        netdev_err(uman_dev, "uman can only enslave ethernet devices.\n");
        return -EPERM;
    }


    /* Old ifenslave binaries are no longer supported.  These can
     * be identified with moderate accuracy by the state of the slave:
     * the current ifenslave will set the interface down prior to
     * enslaving it; the old ifenslave will not.
     */
    if (slave_dev->flags & IFF_UP) {
        netdev_err(uman_dev, "%s is up - this may be due to an out of date ifenslave\n",
               slave_dev->name);
        return -EPERM;
    }

    call_netdevice_notifiers(NETDEV_JOIN, slave_dev);

    if (uman->dev->addr_assign_type == NET_ADDR_RANDOM)
        uman_set_dev_addr(uman->dev, slave_dev);

    new_slave = &uman->slave;
    new_slave->dev = slave_dev;

    /* set slave flag before open to prevent IPv6 addrconf */
    slave_dev->flags |= IFF_SLAVE;

    /* open the slave since the application closed it */
    res = dev_open(slave_dev);
    if (res) {
        netdev_dbg(uman_dev, "Opening slave %s failed\n", slave_dev->name);
        goto err_unslave;
    }

    slave_dev->priv_flags |= IFF_BONDING;

    /* set promiscuity level to new slave */
    if (uman_dev->flags & IFF_PROMISC) {
        res = dev_set_promiscuity(slave_dev, 1);
        if (res)
            goto err_close;
    }

    /* set allmulti level to new slave */
    if (uman_dev->flags & IFF_ALLMULTI) {
        res = dev_set_allmulti(slave_dev, 1);
        if (res)
            goto err_close;
    }

    netif_addr_lock_bh(uman_dev);

    dev_mc_sync_multiple(slave_dev, uman_dev);
    dev_uc_sync_multiple(slave_dev, uman_dev);

    netif_addr_unlock_bh(uman_dev);

    res = netdev_rx_handler_register(slave_dev, uman_handle_frame, uman);
    if (res) {
        netdev_dbg(uman_dev, "Error %d calling netdev_rx_handler_register\n", res);
        goto err_detach;
    }

    res = uman_master_upper_dev_link(uman, new_slave);
    if (res) {
        netdev_dbg(uman_dev, "Error %d calling bond_master_upper_dev_link\n", res);
        goto err_unregister;
    }

    uman_set_carrier(uman);

    netdev_info(uman_dev, "Enslaving %s interface\n", slave_dev->name);

    return 0;

/* Undo stages on error */
err_unregister:
    uman_upper_dev_unlink(uman, new_slave);
    netdev_rx_handler_unregister(slave_dev);

err_detach:
err_close:
    slave_dev->priv_flags &= ~IFF_BONDING;
    dev_close(slave_dev);

err_unslave:
    slave_dev->flags &= ~IFF_SLAVE;
    uman->slave.dev = NULL;
    if (ether_addr_equal_64bits(uman_dev->dev_addr, slave_dev->dev_addr))
        eth_hw_addr_random(uman_dev);

    return res;
}

/* Try to release the slave device <slave> from the bond device <master>
 * It is legal to access curr_active_slave without a lock because all the function
 * is RTNL-locked. If "all" is true it means that the function is being called
 * while destroying a bond interface and all slaves are being released.
 *
 * The rules for slave state should be:
 *   for Active/Backup:
 *     Active stays on all backups go down
 *   for Bonded connections:
 *     The first up interface should be left on and all others downed.
 */
static int uman_emancipate(struct net_device *uman_dev, struct net_device *slave_dev)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave;
    int old_flags = uman_dev->flags;
    VERBOSE_LOG_FUNENTRY();

    if (!slave_dev)
        slave_dev = uman->slave.dev;

    /* slave is not a slave or master is not master of this slave */
    if (!(slave_dev->flags & IFF_SLAVE) || !netdev_has_upper_dev(slave_dev, uman_dev)) {
        netdev_dbg(uman_dev, "cannot release %s\n", slave_dev->name);
        return -EINVAL;
    }

    slave = uman_slave(uman);
    if (!slave) {
        /* not a slave of this uman */
        netdev_info(uman_dev, "%s not enslaved\n", slave_dev->name);
        return -EINVAL;
    }

    uman_upper_dev_unlink(uman, slave);
    /* unregister rx_handler early so uman_handle_frame wouldn't be called
     * for this slave anymore.
     */
    netdev_rx_handler_unregister(slave_dev);

    netdev_info(uman_dev, "Releasing interface %s\n", slave_dev->name);


    uman_set_carrier(uman);
    eth_hw_addr_random(uman_dev);
    call_netdevice_notifiers(NETDEV_CHANGEADDR, uman->dev);
    call_netdevice_notifiers(NETDEV_RELEASE, uman->dev);

    if (old_flags & IFF_PROMISC)
        dev_set_promiscuity(slave_dev, -1);

    if (old_flags & IFF_ALLMULTI)
        dev_set_allmulti(slave_dev, -1);


    /* Flush bond's hardware addresses from slave */
    dev_uc_unsync(slave_dev, uman_dev);
    dev_mc_unsync(slave_dev, uman_dev);


    dev_close(slave_dev);

    slave_dev->priv_flags &= ~IFF_BONDING;

    return 0;
}

void uman_abolish(struct net_device *uman_dev)
{
    uman_emancipate(uman_dev, NULL);
	free_netdev(uman_dev);
}

/*-------------------------------- Interface --------------------------------*/

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
	uman_dev->destructor = uman_abolish;
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

    if (nulpos) {
	    slave_dev = __dev_get_by_name(&init_net, ifname);

	    if (!slave_dev)
		return -EINVAL;

	    printk(DRV_NAME ": (%p) You want to enslave %s@%p (%s)?\n", uman_dev,
		    ifname, slave_dev, slave_dev->name);

	    if ((result = uman_enslave(uman_dev, slave_dev)))
		ret = result;
    } else {
	    if ((result = uman_emancipate(uman_dev, NULL)))
		ret = result;
    }

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
    if (debugfs_dir)
        debugfs_remove_recursive(debugfs_dir);
	unregister_netdev(uman_dev);
	printk(DRV_NAME ": Exiting module\n");
}

module_init(uman_init_module);
module_exit(uman_exit_module);

MODULE_AUTHOR("Ahmad Fatoum");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_VERSION(DRV_VERSION);
