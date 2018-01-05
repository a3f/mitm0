# μman: The micromanaging Linux network driver

A concise example of how a NDIS intermediate-like driver on Linux may be implemented. All net device operations are forwarded to the micromanaged network driver. Incoming packets also first enter μman before they are passed to the networking stack.

μman does so by using the bonding driver API to claim a single network interface completely for itself.

## How to use

some `ifenslave` stuff here

## Why not use pcap?

Good question. Do measurements and post them here.

## Copyright and License

Copyright (C) 2017 Ahmad Fatoum

This kernel module is free software; you can redistribute it and/or modify it under the same terms as Linux itself. See the accompanying `COPYING` file for more information.
