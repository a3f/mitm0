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

#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/if_arp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <net/sch_generic.h>
#include <linux/if_vlan.h>

#include <linux/in.h>
#include <linux/skbuff.h>

#define DRV_VERSION        "0.01"
#define DRV_RELDATE        "2017-01-01"
#define DRV_NAME        "uman"
#define DRV_DESCRIPTION        "Network driver micro-manager"

static char *default_slave; /* TODO */
module_param(default_slave, charp, 0);
MODULE_PARM_DESC(default_slave, "Default slave interface");

int verbose = 1; /* FIXME wasn't there a more idiomatic way? */
/* I think /usr/src/linux/Documentation/dynamic-debug-howto.txt */
module_param(verbose, int, 1);
MODULE_PARM_DESC(verbose, "0 != 1, 1 = narrate every function call");

#define VERBOSE_LOG(...) do { if (verbose) printk(DRV_NAME ": " __VA_ARGS__); } while (0)
#define VERBOSE_LOG_FUNENTRY() VERBOSE_LOG("%s()", __func__)

struct uman {
    struct net_device *dev;
    spinlock_t lock;

    struct slave {
        struct net_device *dev;
    } slave;
};
#define uman_slave_list(uman) (&(uman)->dev->adj_list.lower)
#define uman_has_slave(uman) !list_empty(uman_slave_list(uman))
#define uman_slave(uman) \
    (uman_has_slave(uman) ? netdev_adjacent_get_private(uman_slave_list(uman)->next) : NULL)
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

static void uman_set_dev_mtu(struct net_device *uman_dev, struct net_device *slave_dev)
{
    unsigned long flags;
    spinlock_t *lock = &uman_dev->lock;
    VERBOSE_LOG_FUNENTRY();
    netdev_dbg(uman_dev, "uman_dev=%p slave_dev=%p slave_dev->name=%s slave_dev->addr_len=%d\n",
           uman_dev, slave_dev, slave_dev->name, slave_dev->addr_len);
    spin_lock_irqsave(lock, flags);
    uman_dev->mtu = slave_dev->mtu;
    spin_unlock_irqrestore(lock, flags);
    call_netdevice_notifiers(NETDEV_CHANGEMTU, uman_dev);
}

#define UMAN_VLAN_FEATURES (NETIF_F_HW_CSUM | NETIF_F_SG | \
                            NETIF_F_FRAGLIST | NETIF_F_ALL_TSO | \
                            NETIF_F_HIGHDMA | NETIF_F_LRO)

#define UMAN_ENC_FEATURES        (NETIF_F_HW_CSUM | NETIF_F_SG | \
                                 NETIF_F_RXCSUM | NETIF_F_ALL_TSO)

static void uman_compute_features(struct uman *uman)
{
    struct slave *slave;
    u32 vlan_features = UMAN_VLAN_FEATURES & NETIF_F_ALL_FOR_ALL;
    netdev_features_t enc_features  = UMAN_ENC_FEATURES;
    unsigned short max_hard_header_len = ETH_HLEN;
    unsigned int dst_release_flag = IFF_XMIT_DST_RELEASE | IFF_XMIT_DST_RELEASE_PERM;
    VERBOSE_LOG_FUNENTRY();

    slave = uman_slave(uman);
    if (slave) {
        vlan_features = netdev_increment_features(vlan_features, slave->dev->vlan_features, UMAN_VLAN_FEATURES);
        enc_features = netdev_increment_features(enc_features, slave->dev->hw_enc_features, UMAN_ENC_FEATURES);

        dst_release_flag &= slave->dev->priv_flags;
        if (slave->dev->hard_header_len > max_hard_header_len)
            max_hard_header_len = slave->dev->hard_header_len;
    }

    uman->dev->vlan_features = vlan_features;
    uman->dev->hw_enc_features = enc_features | NETIF_F_GSO_ENCAP_ALL;
    uman->dev->hard_header_len = max_hard_header_len;

    uman->dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
    if (dst_release_flag == (IFF_XMIT_DST_RELEASE | IFF_XMIT_DST_RELEASE_PERM))
        uman->dev->priv_flags |= IFF_XMIT_DST_RELEASE;

    netdev_change_features(uman->dev);
}

static void uman_setup_by_slave(struct net_device *uman_dev, struct net_device *slave_dev)
{
    VERBOSE_LOG_FUNENTRY();
    uman_dev->header_ops      = slave_dev->header_ops;

    uman_dev->type            = slave_dev->type;
    uman_dev->hard_header_len = slave_dev->hard_header_len;
    uman_dev->addr_len        = slave_dev->addr_len;

    memcpy(uman_dev->broadcast, slave_dev->broadcast, slave_dev->addr_len);
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

/*----------------------------- Bonding Setup -------------------------------*/

/* enslave device <slave> to bond device <uman> */
static int uman_enslave(struct net_device *uman_dev, struct net_device *slave_dev)
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

    /* vlan challenged mutual exclusion */
    /* no need to lock since we're protected by rtnl_lock */
    if (slave_dev->features & NETIF_F_VLAN_CHALLENGED) {
        netdev_dbg(uman_dev, "%s is NETIF_F_VLAN_CHALLENGED\n",
               slave_dev->name);
        if (vlan_uses_dev(uman_dev)) {
            netdev_err(uman_dev, "Error: cannot enslave VLAN challenged slave %s on VLAN enabled bond %s\n",
                   slave_dev->name, uman_dev->name);
            return -EPERM;
        } else {
            netdev_warn(uman_dev, "enslaved VLAN challenged slave %s. Adding VLANs will be blocked as long as %s is part of bond %s\n",
                    slave_dev->name, slave_dev->name,
                    uman_dev->name);
        }
    } else {
        netdev_dbg(uman_dev, "%s is !NETIF_F_VLAN_CHALLENGED\n",
               slave_dev->name);
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

    if (uman_dev->type != slave_dev->type) {
        netdev_dbg(uman_dev, "change device type from %d to %d\n",
                uman_dev->type, slave_dev->type);

        res = call_netdevice_notifiers(NETDEV_PRE_TYPE_CHANGE, uman_dev);
        res = notifier_to_errno(res);
        if (res) {
            netdev_err(uman_dev, "refused to change device type\n");
            return -EBUSY;
        }

        /* Flush unicast and multicast addresses */
        dev_uc_flush(uman_dev);
        dev_mc_flush(uman_dev);

        if (slave_dev->type != ARPHRD_ETHER)
            uman_setup_by_slave(uman_dev, slave_dev);
        else {
            ether_setup(uman_dev);
            uman_dev->priv_flags &= ~IFF_TX_SKB_SHARING;
        }

        call_netdevice_notifiers(NETDEV_POST_TYPE_CHANGE, uman_dev);
    }

    call_netdevice_notifiers(NETDEV_JOIN, slave_dev);

    if (uman->dev->addr_assign_type == NET_ADDR_RANDOM)
        uman_set_dev_addr(uman->dev, slave_dev);

    new_slave = &uman->slave;
    new_slave->dev = slave_dev;

    uman_set_dev_mtu(uman->dev, slave_dev);

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

    res = vlan_vids_add_by_dev(slave_dev, uman_dev);
    if (res) {
        netdev_err(uman_dev, "Couldn't add bond vlan ids to %s\n",
               slave_dev->name);
        goto err_close;
    }

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

    /* TODO is this required for ifenslave/ip link add */
#if 0
    res = bond_sysfs_slave_add(new_slave);
    if (res) {
        netdev_dbg(uman_dev, "Error %d calling bond_sysfs_slave_add\n", res);
        goto err_upper_unlink;
    }
#endif

    uman_compute_features(uman);
    uman_set_carrier(uman);

    netdev_info(uman_dev, "Enslaving %s interface\n", slave_dev->name);

    return 0;

/* Undo stages on error */
err_unregister:
    uman_upper_dev_unlink(uman, new_slave);
    netdev_rx_handler_unregister(slave_dev);

err_detach:
    vlan_vids_del_by_dev(slave_dev, uman_dev);

err_close:
    slave_dev->priv_flags &= ~IFF_BONDING;
    dev_close(slave_dev);

err_unslave:
    slave_dev->flags &= ~IFF_SLAVE;
    uman->slave.dev = NULL;
    if (ether_addr_equal_64bits(uman_dev->dev_addr, slave_dev->dev_addr))
        eth_hw_addr_random(uman_dev);
    if (uman_dev->type != ARPHRD_ETHER) {
        dev_close(uman_dev);
        ether_setup(uman_dev);
        uman_dev->flags |= IFF_MASTER;
        uman_dev->priv_flags &= ~IFF_TX_SKB_SHARING;
    }


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

    uman_compute_features(uman);
    vlan_vids_del_by_dev(slave_dev, uman_dev);

    if (old_flags & IFF_PROMISC)
        dev_set_promiscuity(slave_dev, -1);

    if (old_flags & IFF_ALLMULTI)
        dev_set_allmulti(slave_dev, -1);


    /* Flush bond's hardware addresses from slave */
    dev_uc_unsync(slave_dev, uman_dev);
    dev_mc_unsync(slave_dev, uman_dev);


    /* close slave before restoring its mac address */
    dev_close(slave_dev);

    slave_dev->priv_flags &= ~IFF_BONDING;

    return 0;
}

/* First release a slave and then destroy the bond if no more slaves are left.
 * Must be under rtnl_lock when this function is called.
 */
static int uman_emancipate_and_destroy(struct net_device *uman_dev, struct net_device *slave_dev)
{
    struct uman *uman = netdev_priv(uman_dev);
    int ret;
    VERBOSE_LOG_FUNENTRY();

    ret = uman_emancipate(uman_dev, slave_dev);
    if (ret == 0 && !uman_has_slave(uman)) { /* TODO second cond should be unnecessary */
        uman_dev->priv_flags |= IFF_DISABLE_NETPOLL;
        netdev_info(uman_dev, "Destroying bond %s\n", uman_dev->name);
        unregister_netdevice(uman_dev);
    }
    return ret;
}

/*---------------------------- NDO Forwarding -------------------------------*/

static netdev_features_t uman_fix_features(struct net_device *dev, netdev_features_t features)
{
    struct uman *uman = netdev_priv(dev);
    netdev_features_t mask;
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    mask = features;

    features &= ~NETIF_F_ONE_FOR_ALL;
    features |= NETIF_F_ALL_FOR_ALL;

    if (slave)
        features = netdev_increment_features(features, slave->dev->features, mask);

    features = netdev_add_tso_features(features, mask);

    return features;
}

static struct rtnl_link_stats64 *uman_get_stats(struct net_device *uman_dev, struct rtnl_link_stats64 *stats)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    if (slave)
        stats = dev_get_stats(slave->dev, stats);

    return stats;
}

static u16 uman_select_queue(struct net_device *dev, struct sk_buff *skb,
                             void *accel_priv, select_queue_fallback_t fallback)
{
    /* This helper function exists to help dev_pick_tx get the correct
     * destination queue.  Using a helper function skips a call to
     * skb_tx_hash and will put the skbs in the queue we expect on their
     * way down to the bonding driver.
     */
    u16 txq = skb_rx_queue_recorded(skb) ? skb_get_rx_queue(skb) : 0;
    VERBOSE_LOG_FUNENTRY();

    /* Save the original txq to restore before passing to the driver */
    qdisc_skb_cb(skb)->slave_dev_queue_mapping = skb->queue_mapping;

    if (unlikely(txq >= dev->real_num_tx_queues)) {
        do {
            txq -= dev->real_num_tx_queues;
        } while (txq >= dev->real_num_tx_queues);
    }
    return txq;
}

static int uman_change_mtu(struct net_device *uman_dev, int new_mtu)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    int res = 0;
    VERBOSE_LOG_FUNENTRY();

    netdev_dbg(uman_dev, "uman=%p, new_mtu=%d\n", uman, new_mtu);

    if (slave) {
        netdev_dbg(uman_dev, "s %p c_m %p\n", slave, slave->dev->netdev_ops->ndo_change_mtu);

        res = dev_set_mtu(slave->dev, new_mtu);

        if (res) {
            netdev_dbg(uman_dev, "err %d %s\n", res, slave->dev->name);
            return res;
        }
    }

    uman_dev->mtu = new_mtu;

    return 0;
}

/* Change HW address
 *
 * Note that many devices must be down to change the HW address
 */
static int uman_set_mac_address(struct net_device *uman_dev, void *addr)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    struct sockaddr *sa = addr;
    int res = 0;
    VERBOSE_LOG_FUNENTRY();

    netdev_dbg(uman_dev, "uman=%p\n", uman);

    if (!is_valid_ether_addr((u8*)sa->sa_data))
        return -EADDRNOTAVAIL;

    if (slave) {
        netdev_dbg(uman_dev, "slave %p %s\n", slave, slave->dev->name);
        res = dev_set_mac_address(slave->dev, addr);
        if (res) {
            netdev_dbg(uman_dev, "err %d %s\n", res, slave->dev->name);
            return res;
        }
    }

    /* success */
    memcpy(uman_dev->dev_addr, sa->sa_data, uman_dev->addr_len);
    return 0;
}

static void uman_change_rx_flags(struct net_device *uman_dev, int change)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    if (!slave)
        return;

    if (change & IFF_PROMISC)
        dev_set_promiscuity(slave->dev, uman_dev->flags & IFF_PROMISC ? 1 : -1);

    if (change & IFF_ALLMULTI)
        dev_set_allmulti(slave->dev, uman_dev->flags & IFF_ALLMULTI ? 1 : -1);
}

static void uman_set_rx_mode(struct net_device *uman_dev)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();

    if (!slave)
        return;

    dev_uc_sync(slave->dev, uman_dev);
    dev_mc_sync(slave->dev, uman_dev);
}

/*-------------------------- netdev event handling --------------------------*/

static const char *const __event_string_of[] = {
    [0]                           = "<no event>",
    [NETDEV_UP]                   = "NETDEV_UP", /* For now you can't veto a device up/down */
    [NETDEV_DOWN]                 = "NETDEV_DOWN",
    [NETDEV_REBOOT]               = "NETDEV_REBOOT", /* Tell a protocol stack a network interface
                                          detected a hardware crash and restarted
                                          - we can use this eg to kick tcp sessions
                                          once done */
    [NETDEV_CHANGE]               = "NETDEV_CHANGE", /* Notify device state change */
    [NETDEV_REGISTER]             = "NETDEV_REGISTER",
    [NETDEV_UNREGISTER]           = "NETDEV_UNREGISTER",
    [NETDEV_CHANGEMTU]            = "NETDEV_CHANGEMTU", /* notify after mtu change happened */
    [NETDEV_CHANGEADDR]           = "NETDEV_CHANGEADDR",
    [NETDEV_GOING_DOWN]           = "NETDEV_GOING_DOWN",
    [NETDEV_CHANGENAME]           = "NETDEV_CHANGENAME",
    [NETDEV_FEAT_CHANGE]          = "NETDEV_FEAT_CHANGE",
    [NETDEV_BONDING_FAILOVER]     = "NETDEV_BONDING_FAILOVER",
    [NETDEV_PRE_UP]               = "NETDEV_PRE_UP",
    [NETDEV_PRE_TYPE_CHANGE]      = "NETDEV_PRE_TYPE_CHANGE",
    [NETDEV_POST_TYPE_CHANGE]     = "NETDEV_POST_TYPE_CHANGE",
    [NETDEV_POST_INIT]            = "NETDEV_POST_INIT",
    [NETDEV_UNREGISTER_FINAL]     = "NETDEV_UNREGISTER_FINAL",
    [NETDEV_RELEASE]              = "NETDEV_RELEASE",
    [NETDEV_NOTIFY_PEERS]         = "NETDEV_NOTIFY_PEERS",
    [NETDEV_JOIN]                 = "NETDEV_JOIN",
    [NETDEV_CHANGEUPPER]          = "NETDEV_CHANGEUPPER",
    [NETDEV_RESEND_IGMP]          = "NETDEV_RESEND_IGMP",
    [NETDEV_PRECHANGEMTU]         = "NETDEV_PRECHANGEMTU", /* notify before mtu change happened */
    [NETDEV_CHANGEINFODATA]       = "NETDEV_CHANGEINFODATA",
    [NETDEV_BONDING_INFO]         = "NETDEV_BONDING_INFO",
    [NETDEV_PRECHANGEUPPER]       = "NETDEV_PRECHANGEUPPER",
    [NETDEV_CHANGELOWERSTATE]     = "NETDEV_CHANGELOWERSTATE",
    [NETDEV_UDP_TUNNEL_PUSH_INFO] = "NETDEV_UDP_TUNNEL_PUSH_INFO",
    [NETDEV_CHANGE_TX_QUEUE_LEN]  = "NETDEV_CHANGE_TX_QUEUE_LEN",

    NULL
};
#define LAST_NETDEV_EVENT (NETDEV_CHANGE_TX_QUEUE_LEN+1)
static inline const char *event_string_of(unsigned long event) {
    if (event >= LAST_NETDEV_EVENT)
        return "<out of bounds>";

    return __event_string_of[event];
}

static int uman_slave_netdev_event(unsigned long event, struct net_device *slave_dev)
{
    struct uman *uman = rtnl_dereference(slave_dev->rx_handler_data);
    VERBOSE_LOG_FUNENTRY();

    /* A netdev event can be generated while enslaving a device
     * before netdev_rx_handler_register is called in which case
     * slave will be NULL
     */
    if (!uman_slave(uman))
        return NOTIFY_DONE;

    switch (event) {
        case NETDEV_UNREGISTER:
            if (uman->dev->type != ARPHRD_ETHER)
                uman_emancipate_and_destroy(uman->dev, slave_dev);
            else
                uman_emancipate(uman->dev, slave_dev);
            break;
        case NETDEV_FEAT_CHANGE:
            uman_compute_features(uman);
            break;
        case NETDEV_CHANGEMTU:
        case NETDEV_CHANGENAME:
        case NETDEV_RESEND_IGMP:
        case NETDEV_UP:
        case NETDEV_CHANGE:
        case NETDEV_DOWN:
        default:
            break;
    }

    return NOTIFY_DONE;
}

/* bond_netdev_event: handle netdev notifier chain events.
 *
 * This function receives events for the netdev chain.  The caller (an
 * ioctl handler calling blocking_notifier_call_chain) holds the necessary
 * locks for us to safely manipulate the slave devices (RTNL lock,
 * dev_probe_lock).
 */
static int uman_netdev_event(struct notifier_block *this,
        unsigned long event, void *ptr)
{
    struct net_device *event_dev = netdev_notifier_info_to_dev(ptr);
    VERBOSE_LOG_FUNENTRY();

    netdev_dbg(event_dev, "event: %s (%lx)\n", event_string_of(event), event);

    if (!(event_dev->priv_flags & IFF_BONDING))
        return NOTIFY_DONE;

    if (event_dev->flags & IFF_MASTER)
        return NOTIFY_DONE; /* we don't have any procfs, sysfs or debugfs to sync */

    if (event_dev->flags & IFF_SLAVE) {
        netdev_dbg(event_dev, "IFF_SLAVE\n");
        return uman_slave_netdev_event(event, event_dev);
    }

    return NOTIFY_DONE;
}

static struct notifier_block uman_netdev_notifier = {
    .notifier_call = uman_netdev_event,
};

/*--------------------------------- DebugFS ---------------------------------*/
static struct dentry *debugfs_dir;
static ssize_t debugfs_get_slave(struct file *file, char __user *buff, size_t count, loff_t *offset)
{
    struct net_device *uman_dev = file->f_inode->i_private;
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);

    if (!debugfs_dir)
        return -EIO;

    if (!slave)
        return -EAGAIN;

    return simple_read_from_buffer(buff, count, offset, slave->dev->name, strlen(slave->dev->name));
}
static ssize_t debugfs_set_slave(struct file *file, const char __user *buff, size_t count, loff_t *offset)
{
    struct net_device *uman_dev = file->f_inode->i_private;
    struct net_device *slave_dev;
    char ifname[IFNAMSIZ+1];
    ssize_t ret, nulpos;
    int result;

    if (!debugfs_dir)
        return -EIO;

    ret = simple_write_to_buffer(ifname, sizeof ifname - 1, offset, buff, count);
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

    printk(DRV_NAME ": (%p) You want to enslave %s@%p (%s)?\n", uman_dev, ifname, slave_dev, slave_dev->name);

    if ((result = uman_enslave(uman_dev, slave_dev)))
        ret = result;

    rtnl_unlock();

    return ret;
}
static const struct file_operations slave_fops = {
    .owner = THIS_MODULE,
    .read  = debugfs_get_slave,
    .write = debugfs_set_slave,
};

/*-------------------------------- Interface --------------------------------*/


/*
 * Open and close
 */

static int uman_open(struct net_device *dev)
{
    VERBOSE_LOG_FUNENTRY();
    /* Neither bond not team call netif_(start|stop)_queue. why? */
    /* netif_start_queue(dev); */
    return 0;
}

static int uman_stop(struct net_device *dev)
{
    VERBOSE_LOG_FUNENTRY();
    /* netif_stop_queue(dev); */
    return 0;
}

static const struct ethtool_ops uman_ethtool_ops;
static const struct net_device_ops uman_netdev_ops;

/*
 * Finally, the module stuff
 */

static int uman_init(struct net_device *uman_dev)
{
    VERBOSE_LOG_FUNENTRY();

    netdev_lockdep_set_classes(uman_dev);

    /* Ensure valid dev_addr */
    if (is_zero_ether_addr(uman_dev->dev_addr) &&
        uman_dev->addr_assign_type == NET_ADDR_PERM)
            eth_hw_addr_random(uman_dev);

    return 0;
}

static void uman_uninit(struct net_device *uman_dev)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave = uman_slave(uman);
    VERBOSE_LOG_FUNENTRY();
    if (slave)
        uman_emancipate_and_destroy(uman_dev, slave->dev);
}

static const struct device_type uman_type = {
    .name = "uman",
};

static void uman_setup(struct net_device *uman_dev)
{
    struct uman *uman = netdev_priv(uman_dev);
    VERBOSE_LOG_FUNENTRY();

    uman->dev = uman_dev;
    uman->slave.dev = NULL;

    ether_setup(uman_dev); /* assign some of the fields */

    uman_dev->netdev_ops   = &uman_netdev_ops;
    uman_dev->ethtool_ops  = &uman_ethtool_ops;

    uman_dev->destructor = free_netdev; /* TODO is this necessary? */

    SET_NETDEV_DEVTYPE(uman_dev, &uman_type);

    /* Initialize the device options */
    uman_dev->flags      |= IFF_MASTER;
    uman_dev->priv_flags |= IFF_BONDING | IFF_UNICAST_FLT | IFF_NO_QUEUE;
    uman_dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_TX_SKB_SHARING);

    uman_dev->features |= NETIF_F_HW_CSUM;
    uman_dev->features |= NETIF_F_LLTX;
}

static void __exit uman_exit_module(void)
{
    VERBOSE_LOG_FUNENTRY();
    if (debugfs_dir)
        debugfs_remove_recursive(debugfs_dir);
    unregister_netdevice_notifier(&uman_netdev_notifier);
    printk(DRV_NAME ": Exiting module\n");
}

static int __init uman_init_module(void)
{
    int ret;
    struct net_device *uman_dev;
    VERBOSE_LOG_FUNENTRY();

    register_netdevice_notifier(&uman_netdev_notifier);

    uman_dev = alloc_netdev(sizeof(struct uman), "uman%d", NET_NAME_UNKNOWN, uman_setup);

    if (!uman_dev)
        return -ENOMEM;

    if ((ret = register_netdev(uman_dev))) {
        printk("uman: error %i registering device \"%s\"\n", ret, uman_dev->name);
        free_netdev(uman_dev);
        return -ENODEV;
    }

    debugfs_dir = debugfs_create_dir(uman_dev->name, NULL);
    if (IS_ERR_OR_NULL(debugfs_dir)) {
        printk(KERN_ALERT DRV_NAME ": failed to create /sys/kernel/debug/%s\n", uman_dev->name);
        debugfs_dir = NULL;
    } else {
        struct dentry *dentry = debugfs_create_file("slave", 0600, debugfs_dir, uman_dev, &slave_fops);
        if (IS_ERR_OR_NULL(dentry)) {
            printk(KERN_ALERT DRV_NAME ": failed to create /sys/kernel/debug/%s/slave\n", uman_dev->name);
        }
    }

    printk(DRV_NAME ": Initialized module with interface %s@%p\n", uman_dev->name, uman_dev);

    return 0;
}


static int uman_ethtool_get_link_ksettings(struct net_device *uman_dev,
            struct ethtool_link_ksettings *ecmd)
{
    struct uman *uman = netdev_priv(uman_dev);
    struct slave *slave;
    VERBOSE_LOG_FUNENTRY();

    slave = uman_slave(uman);
    if (slave)
        return __ethtool_get_link_ksettings(slave->dev, ecmd);

    return 0;
}

static void uman_ethtool_get_drvinfo(struct net_device *uman_dev,
                                     struct ethtool_drvinfo *drvinfo)
{
    VERBOSE_LOG_FUNENTRY();
    strlcpy(drvinfo->driver, DRV_NAME, sizeof(drvinfo->driver));
    strlcpy(drvinfo->version, DRV_VERSION, sizeof(drvinfo->version));
#if 0
    snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version), "%d", BOND_ABI_VERSION);
#endif
}

static const struct ethtool_ops uman_ethtool_ops = {
    .get_drvinfo                  = uman_ethtool_get_drvinfo,
    .get_link_ksettings           = uman_ethtool_get_link_ksettings,
    .get_link                     = ethtool_op_get_link,
};

static const struct net_device_ops uman_netdev_ops = {
    .ndo_init                     = uman_init,
    .ndo_uninit                   = uman_uninit,
    .ndo_open                     = uman_open,
    .ndo_stop                     = uman_stop,

    .ndo_start_xmit               = uman_start_xmit,
    .ndo_select_queue             = uman_select_queue,

    .ndo_get_stats64              = uman_get_stats,
    .ndo_set_mac_address          = uman_set_mac_address,
    .ndo_change_mtu               = uman_change_mtu,
    .ndo_change_rx_flags          = uman_change_rx_flags,
    .ndo_set_rx_mode              = uman_set_rx_mode,
    .ndo_fix_features             = uman_fix_features,

    .ndo_add_slave                = uman_enslave,
    .ndo_del_slave                = uman_emancipate,
};



module_init(uman_init_module);
module_exit(uman_exit_module);

MODULE_AUTHOR("Ahmad Fatoum");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_VERSION(DRV_VERSION);
