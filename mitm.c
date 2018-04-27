/*
 * mitm.c  --  man-in-the-middle another network interface
 * Copyright (C) 2017 Ahmad Fatoum
 *
 * Based on the drivers/net/bonding/bond_main.c
 * Copyright 1999, Thomas Davis, tadavis@lbl.gov.
 * Licensed under the GPL. Itself based on dummy.c, and eql.c devices.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/rtnetlink.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netpoll.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/sch_generic.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#define DRV_VERSION        "0.01"
#define DRV_RELDATE        "2017-01-01"
#define DRV_NAME           "mitm"
#define DRV_DESCRIPTION    "Network driver Man-In-The-Middle'r"

static bool use_qdisc = true;
module_param(use_qdisc, bool, 0);
MODULE_PARM_DESC(use_qdisc, "Use Qdisc? 0 = no, 1 = yes (default)");

static bool use_netpoll = false;
#ifdef CONFIG_NETPOLL
MODULE_PARM_DESC(use_netpoll, "Use netpoll if possible? 0 = no (default), 1 = yes");
module_param(use_netpoll, bool, 0);
#endif


/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct mitm {
	struct net_device *dev;
	spinlock_t lock;

#ifdef CONFIG_NETPOLL
        struct netpoll np;
#endif
        netdev_tx_t (*xmit)(struct mitm *mitm, struct sk_buff *);

	struct slave {
		struct net_device *dev;
	} slave;
};

#define mitm_slave_list(mitm) (&(mitm)->dev->adj_list.lower)
#define mitm_has_slave(mitm) !list_empty(mitm_slave_list(mitm))
#define mitm_slave(mitm) (mitm_has_slave(mitm) ? \
	netdev_adjacent_get_private(mitm_slave_list(mitm)->next) : NULL)
#define mitm_of(slaveptr) container_of((slaveptr), struct mitm, slave)

/*----------------------------------- Rx ------------------------------------*/

/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
static rx_handler_result_t mitm_handle_frame(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    struct mitm *mitm;

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (unlikely(!skb))
        return RX_HANDLER_CONSUMED;

    *pskb = skb;

    mitm = rcu_dereference(skb->dev->rx_handler_data);

    skb->dev = mitm->dev;

    return RX_HANDLER_ANOTHER; /* Do another round in receive path */
}


/*----------------------------------- Tx ------------------------------------*/

static int __packet_direct_xmit(struct sk_buff *skb);

static netdev_tx_t mitm_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    netdev_tx_t ret = NETDEV_TX_OK;
    struct mitm *mitm = netdev_priv(dev);
    struct slave *slave = mitm_slave(mitm);

    BUILD_BUG_ON(sizeof(skb->queue_mapping) !=
             sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
    skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);

#if 0 /* we could use this for notification of tx if we are sure no one else uses it */
    skb_shinfo(skb)->destructor_arg = pBuffer_p;
    skb->destructor = txPacketHandler;
#endif

    /* TODO rcu lock? */
    if (slave) {
        skb->dev = slave->dev;
        ret = mitm->xmit(mitm, skb);
    } else {
        atomic_long_inc(&dev->tx_dropped);
        dev_kfree_skb_any(skb);
    }


    return ret;
}
static inline netdev_tx_t __packet_xmit_irq_enabled(netdev_tx_t (*xmit)(struct sk_buff *), struct sk_buff *skb)
{
    netdev_tx_t ret;
    bool enable_irq = irqs_disabled(); /* always false in our current setup, but your use case may change */

    if (enable_irq) local_irq_enable();
    ret = xmit(skb);
    if (enable_irq) local_irq_disable();

    return ret;
}
static netdev_tx_t packet_queue_xmit(struct mitm *mitm, struct sk_buff *skb)
{
    BUILD_BUG_ON(sizeof(skb->queue_mapping) !=
            sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
    skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);

    return __packet_xmit_irq_enabled(dev_queue_xmit, skb);
}
static netdev_tx_t packet_direct_xmit(struct mitm *mitm, struct sk_buff *skb)
{
    return __packet_xmit_irq_enabled(__packet_direct_xmit, skb);
}
static netdev_tx_t packet_netpoll_xmit(struct mitm *mitm, struct sk_buff *skb)
{
#ifdef CONFIG_NETPOLL
    netpoll_send_skb(&mitm->np, skb);
#endif
    return NETDEV_TX_OK;
}

/* Taken out of net/packet/af_packet.c */
static u16 __packet_pick_tx_queue(struct net_device *dev, struct sk_buff *skb)
{
	return (u16) raw_smp_processor_id() % dev->real_num_tx_queues;
}


static void packet_pick_tx_queue(struct net_device *dev, struct sk_buff *skb)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	u16 queue_index;

	if (ops->ndo_select_queue)
        {
		queue_index = ops->ndo_select_queue(dev, skb, NULL,
						    __packet_pick_tx_queue);
		queue_index = netdev_cap_txqueue(dev, queue_index);
	} else {
		queue_index = __packet_pick_tx_queue(dev, skb);
	}

	skb_set_queue_mapping(skb, queue_index);
}
static int __packet_direct_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct sk_buff *orig_skb = skb;
	struct netdev_queue *txq;
	int ret = NETDEV_TX_BUSY;

	if (unlikely(!netif_running(dev) ||
		     !netif_carrier_ok(dev)))
		goto drop;

	skb = validate_xmit_skb_list(skb, dev);
	if (skb != orig_skb)
		goto drop;

	packet_pick_tx_queue(dev, skb);
	txq = skb_get_tx_queue(dev, skb);

	local_bh_disable();

	HARD_TX_LOCK(dev, txq, smp_processor_id());
	if (!netif_xmit_frozen_or_drv_stopped(txq))
		ret = netdev_start_xmit(skb, dev, txq, false);
	HARD_TX_UNLOCK(dev, txq);

	local_bh_enable();

	if (!dev_xmit_complete(ret))
		kfree_skb(skb);

	return ret;
drop:
	atomic_long_inc(&dev->tx_dropped);
	kfree_skb_list(skb);
	return NET_XMIT_DROP;
}

/*-------------------------- Bonding Notification ---------------------------*/

static int mitm_master_upper_dev_link(struct mitm *mitm, struct net_device *slave_dev)
{
    int err;
    /* we aggregate everything into one link, so that's technically a broadcast */
    struct netdev_lag_upper_info lag_upper_info = {
        .tx_type = NETDEV_LAG_TX_TYPE_BROADCAST
    };

    err = netdev_master_upper_dev_link(slave_dev, mitm->dev, slave_dev, &lag_upper_info);
    if (err)
        return err;
    rtmsg_ifinfo(RTM_NEWLINK, slave_dev, IFF_SLAVE, GFP_KERNEL);
    return 0;
}

static void mitm_upper_dev_unlink(struct mitm *mitm, struct net_device *slave_dev)
{
    netdev_upper_dev_unlink(slave_dev, mitm->dev);
    slave_dev->flags &= ~IFF_SLAVE;
    rtmsg_ifinfo(RTM_NEWLINK, slave_dev, IFF_SLAVE, GFP_KERNEL);
}
/* FIXME unused */
#if 0
static void bond_lower_state_changed(struct slave *slave)
{
    struct netdev_lag_lower_state_info info;

    info.link_up = slave->link_up;
    info.tx_enabled = slave->dev != NULL;
    netdev_lower_state_changed(slave->dev, &info);
}
#endif

/**
 * mitm_set_dev_addr - clone slave's address to bond
 * @mitm_dev: bond net device
 * @slave_dev: slave net device
 *
 * Should be called with RTNL held.
 */
static void mitm_set_dev_addr(struct net_device *mitm_dev, struct net_device *slave_dev)
{
    netdev_dbg(mitm_dev, "mitm_dev=%p slave_dev=%p slave_dev->name=%s slave_dev->addr_len=%d\n",
           mitm_dev, slave_dev, slave_dev->name, slave_dev->addr_len);
    memcpy(mitm_dev->dev_addr, slave_dev->dev_addr, slave_dev->addr_len);
    mitm_dev->addr_assign_type = NET_ADDR_STOLEN;
    call_netdevice_notifiers(NETDEV_CHANGEADDR, mitm_dev);
}

/* Set carrier state of master on if there's a slave
 *
 * Returns zero if carrier state does not change, nonzero if it does.
 */
static int mitm_set_carrier(struct mitm *mitm)
{
    struct slave *slave = mitm_slave(mitm);

    if (!slave) {
	if (netif_carrier_ok(mitm->dev)) {
	    netif_carrier_off(mitm->dev);
	    return 1;
	}

	return 0;
    }

    if (!netif_carrier_ok(mitm->dev)) {
        netif_carrier_on(mitm->dev);
        return 1;
    }

    return 0;
}


/*--------------------------------- Slavery ---------------------------------*/

static int mitm_enslave(struct net_device *mitm_dev,
		struct net_device *slave_dev)
{
    struct mitm *mitm = netdev_priv(mitm_dev);
    int res = 0;

    /* We only mitm one device */
    if (mitm_has_slave(mitm)) {
        netdev_err(mitm_dev, "Error: mitm can only have one slave\n");
        return -EBUSY;
    }

    /* already in-use? */
    if (netdev_is_rx_handler_busy(slave_dev)) {
        netdev_err(mitm_dev, "Error: Device is in use and cannot be enslaved\n");
        return -EBUSY;
    }

    if (mitm_dev == slave_dev) {
        netdev_err(mitm_dev, "mitm cannot enslave itself.\n");
        return -EPERM;
    }

    if (slave_dev->type != ARPHRD_ETHER) {
        netdev_err(mitm_dev, "mitm can only enslave ethernet devices.\n");
        return -EPERM;
    }


    /* Old ifenslave binaries are no longer supported.  These can
     * be identified with moderate accuracy by the state of the slave:
     * the current ifenslave will set the interface down prior to
     * enslaving it; the old ifenslave will not.
     */
    if (slave_dev->flags & IFF_UP) {
        netdev_err(mitm_dev, "%s is up - this may be due to an out of date ifenslave\n",
               slave_dev->name);
        return -EPERM;
    }

    call_netdevice_notifiers(NETDEV_JOIN, slave_dev);

    mitm_set_dev_addr(mitm->dev, slave_dev);

    mitm->slave.dev = slave_dev;

    /* set slave flag before open to prevent IPv6 addrconf */
    slave_dev->flags |= IFF_SLAVE;

    /* open the slave since the application closed it */
    res = dev_open(slave_dev);
    if (res) {
        netdev_err(mitm_dev, "Opening slave %s failed\n", slave_dev->name);
        goto err_unslave;
    }

    slave_dev->priv_flags |= IFF_BONDING;

    /* set promiscuity level to new slave */
    if (mitm_dev->flags & IFF_PROMISC) {
        res = dev_set_promiscuity(slave_dev, 1);
        if (res)
            goto err_close;
    }

    /* set allmulti level to new slave */
    if (mitm_dev->flags & IFF_ALLMULTI) {
        res = dev_set_allmulti(slave_dev, 1);
        if (res)
            goto err_close;
    }

    netif_addr_lock_bh(mitm_dev);

    dev_mc_sync_multiple(slave_dev, mitm_dev);
    dev_uc_sync_multiple(slave_dev, mitm_dev);

    netif_addr_unlock_bh(mitm_dev);

    res = netdev_rx_handler_register(slave_dev, mitm_handle_frame, mitm);
    if (res) {
        netdev_err(mitm_dev, "Error %d calling netdev_rx_handler_register\n", res);
        goto err_detach;
    }

    res = mitm_master_upper_dev_link(mitm, slave_dev);
    if (res) {
        netdev_err(mitm_dev, "Error %d calling bond_master_upper_dev_link\n", res);
        goto err_unregister;
    }

    mitm_set_carrier(mitm);

    netdev_info(mitm_dev, "Enslaving %s interface\n", slave_dev->name);

    return 0;

/* Undo stages on error */
err_unregister:
    mitm_upper_dev_unlink(mitm, slave_dev);
    netdev_rx_handler_unregister(slave_dev);

err_detach:
err_close:
    slave_dev->priv_flags &= ~IFF_BONDING;
    dev_close(slave_dev);

err_unslave:
    slave_dev->flags &= ~IFF_SLAVE;
    mitm->slave.dev = NULL;
    if (ether_addr_equal_64bits(mitm_dev->dev_addr, slave_dev->dev_addr))
        eth_hw_addr_random(mitm_dev);

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
static int mitm_emancipate(struct net_device *mitm_dev, struct net_device *slave_dev)
{
    struct mitm *mitm = netdev_priv(mitm_dev);
    struct slave *slave;
    int old_flags = mitm_dev->flags;

    if (!slave_dev)
        slave_dev = mitm->slave.dev;

    if (!slave_dev)
        return 0; /* nothing to do */

    /* slave is not a slave or master is not master of this slave */
    if (!(slave_dev->flags & IFF_SLAVE) || !netdev_has_upper_dev(slave_dev, mitm_dev)) {
        netdev_err(mitm_dev, "cannot release %s\n", slave_dev->name);
        return -EINVAL;
    }

    slave = mitm_slave(mitm);
    if (!slave) {
        /* not a slave of this mitm */
        netdev_err(mitm_dev, "%s not enslaved\n", slave_dev->name);
        return -EINVAL;
    }

    mitm_upper_dev_unlink(mitm, slave_dev);
    /* unregister rx_handler early so mitm_handle_frame wouldn't be called
     * for this slave anymore.
     */
    netdev_rx_handler_unregister(slave_dev);

    netdev_info(mitm_dev, "Releasing interface %s\n", slave_dev->name);


    mitm_set_carrier(mitm);
    eth_hw_addr_random(mitm_dev);
    call_netdevice_notifiers(NETDEV_CHANGEADDR, mitm->dev);
    call_netdevice_notifiers(NETDEV_RELEASE, mitm->dev);

    if (old_flags & IFF_PROMISC)
        dev_set_promiscuity(slave_dev, -1);

    if (old_flags & IFF_ALLMULTI)
        dev_set_allmulti(slave_dev, -1);


    /* Flush bond's hardware addresses from slave */
    dev_uc_unsync(slave_dev, mitm_dev);
    dev_mc_unsync(slave_dev, mitm_dev);


    dev_close(slave_dev);

    slave_dev->priv_flags &= ~IFF_BONDING;

    return 0;
}

/*-------------------------------- Interface --------------------------------*/

/*
 * Open and close
 */
int mitm_open(struct net_device *dev)
{
	/* Neither bond not team call netif_(start|stop)_queue. why? */
	/* netif_start_queue(dev); */
	return 0;
}

int mitm_stop(struct net_device *dev)
{
	/* netif_stop_queue(dev); */
	return 0;
}

static const struct net_device_ops mitm_netdev_ops = {
	.ndo_open		= mitm_open,
	.ndo_stop		= mitm_stop,
	.ndo_start_xmit		= mitm_start_xmit,
};

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void mitm_setup(struct net_device *mitm_dev)
{
	struct mitm *mitm = netdev_priv(mitm_dev);

	spin_lock_init(&mitm->lock);
	mitm->dev = mitm_dev;
	mitm->slave.dev = NULL;

	ether_setup(mitm_dev); /* assign some of the fields */

	mitm_dev->netdev_ops = &mitm_netdev_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,9)
        mitm_dev->needs_free_netdev = true;
#else
	mitm_dev->destructor = free_netdev;
#endif

}

/*--------------------------------- DebugFS ---------------------------------*/
static struct dentry *debugfs_dir;
static ssize_t debugfs_get_slave(struct file *file, char __user *buff,
	size_t count, loff_t *offset)
{
    struct net_device *mitm_dev = file->f_inode->i_private;
    struct mitm *mitm = netdev_priv(mitm_dev);
    struct slave *slave = mitm_slave(mitm);

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
    struct net_device *mitm_dev = file->f_inode->i_private;
    struct mitm *mitm = netdev_priv(mitm_dev);
    struct net_device *slave_dev;
    char ifname[IFNAMSIZ+1];
    ssize_t ret, nulpos;
    int result;

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

	    printk(DRV_NAME ": (%p) You want to enslave %s@%p (%s)?\n", mitm_dev,
		    ifname, slave_dev, slave_dev->name);

	    if ((result = mitm_enslave(mitm_dev, slave_dev)))
		ret = result;

#ifdef CONFIG_NETPOLL
        if (use_netpoll)
        {
            mitm->np.name = "oplk-edrv-bridge";
            strlcpy(mitm->np.dev_name, slave_dev->name, IFNAMSIZ);
            ret = __netpoll_setup(&mitm->np, slave_dev);
            if (ret < 0)
            {
                printk(KERN_ERR "%s() Failed to setup netpoll for %s: error %zd\n", __func__, slave_dev->name, ret);
                mitm->np.dev = NULL;
                goto unlock;
            }
        }
#endif

    mitm->xmit = use_qdisc   ? packet_queue_xmit
               : use_netpoll ? packet_netpoll_xmit
               :               packet_direct_xmit;

    printk("mitm%s: %s mode will be used on %s\n", mitm_dev->name,
            use_qdisc   ? "Qdisc" :
            use_netpoll ? "Netpoll" :
                          "Direct-xmit",
            slave_dev->name);

    } else {
            mitm->xmit = NULL; /* FIXME might be racy... */
#ifdef CONFIG_NETPOLL
            if (mitm->np.dev) {
                netpoll_cleanup(&mitm->np);
                mitm->np.dev = NULL;
            }
#endif
	    if ((result = mitm_emancipate(mitm_dev, NULL)))
		ret = result;
    }

unlock:
    rtnl_unlock();
    return ret;
}
static const struct file_operations slave_fops = {
    .owner = THIS_MODULE,
    .read  = debugfs_get_slave,
    .write = debugfs_set_slave,
};

/*---------------------------- Module init/fini -----------------------------*/
static struct net_device *mitm_dev;



int __init mitm_init_module(void)
{
	int ret;

	/* Allocate the devices */
	mitm_dev = alloc_netdev(sizeof(struct mitm), "mitm%d",
		NET_NAME_UNKNOWN, mitm_setup);
	if (!mitm_dev)
		return -ENOMEM;

	if ((ret = register_netdev(mitm_dev))) {
		printk(DRV_NAME ": error %i registering device \"%s\"\n",
				ret, mitm_dev->name);
		unregister_netdev(mitm_dev);
		return -ENODEV;
	}

	debugfs_dir = debugfs_create_dir(mitm_dev->name, NULL);
	if (IS_ERR_OR_NULL(debugfs_dir)) {
		printk(KERN_ALERT DRV_NAME ": failed to create /sys/kernel/debug/%s\n",
            mitm_dev->name);
		debugfs_dir = NULL;
	} else {
		struct dentry *dentry = debugfs_create_file("slave", 0600, debugfs_dir,
            mitm_dev, &slave_fops);
		if (IS_ERR_OR_NULL(dentry)) {
			printk(KERN_ALERT DRV_NAME ": failed to create /sys/kernel/debug/%s/slave\n",
            mitm_dev->name);
		}
	}

	printk(DRV_NAME ": Initialized module with interface %s@%p\n", mitm_dev->name, mitm_dev);

	return 0;
}

void __exit mitm_exit_module(void)
{
    if (debugfs_dir)
        debugfs_remove_recursive(debugfs_dir);
    rtnl_lock();
    mitm_emancipate(mitm_dev, NULL);
    rtnl_unlock();
	unregister_netdev(mitm_dev);
	printk(DRV_NAME ": Exiting module\n");
}

module_init(mitm_init_module);
module_exit(mitm_exit_module);


MODULE_AUTHOR("Ahmad Fatoum");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_VERSION(DRV_VERSION);
