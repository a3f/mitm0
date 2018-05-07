# mitm0: Man-in-the-middle another Linux network driver [![Build Status](https://travis-ci.org/a3f/mitm0.svg?branch=master)](https://travis-ci.org/a3f/mitm0)

A concise example of how a NDIS intermediate-like driver on Linux may be implemented. Net device operations are forwarded to the micromanaged network driver. Incoming packets enter the driver first as well before they are passed to the networking stack.

mitm0 (formerly μman) uses the same mechanisms as the Linux switching API to control/mitm/micro-manage a single network interface.

## How to use

You can read/write `/sys/kernel/debug/mitm0/slave` to set the slave interface (`echo > /sys/kernel/debug/mitm0/slave` to free slave).

## Why not use pcap?

pcap does passive sniffing. mitm0 allows for mangling/dropping traffic as well. Even if you don't mangle traffic, using mitm0 to implement your protocol in kernelspace has a tangible effect on latency:

![rpi-pollreq-pollres][rpi-pollreq-pollres]

Figure shows the reaction times of the openPOWERLINK stack when run in userspace using pcap and when run in kernelspace using a [mitm-based driver]. This was measured on a Raspberry Pi 3 with Linux v4.9 and the PREEMPT\_RT patchset. The measurement took an hour, cycle frequency was 200Hz and hackbench was running in the background.

## Copyright and License

Copyright (C) 2018 Ahmad Fatoum

This kernel module is free software; you can redistribute it and/or modify it under the same terms as Linux itself. See the accompanying `COPYING` file for more information.

[rpi-pollreq-pollres]: https://github.com/a3f/mitm0/blob/master/CN-rpi-4-9-rt-nopm-hackbench-720k.png
[mitm-based driver]: https://github.com/a3f/openPOWERLINK_V2
