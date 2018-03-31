# μman: The micromanaging Linux network driver

A concise example of how a NDIS intermediate-like driver on Linux may be implemented. All net device operations are forwarded to the micromanaged network driver. Incoming packets also first enter μman before they are passed to the networking stack.

μman does so by uses the same mechanisms as the Linux switching API to control a single network interface.

## How to use

You can read/write `/sys/kernel/debug/uman0/slave` to set the slave interface (`echo > /sys/kernel/debug/uman0/slave` to free slave). I experiences some rather high latency outliers with netpoll, so you should probably set `use_qdisc=1 use_netpoll=0` at module load time.

## Why not use pcap?

pcap does passic sniffing. This intercepts all traffic.

## Copyright and License

Copyright (C) 2017 Ahmad Fatoum

This kernel module is free software; you can redistribute it and/or modify it under the same terms as Linux itself. See the accompanying `COPYING` file for more information.
