node-nfqueue
============

This is a node.js binding to the linux netfilter NFQUEUE. It allows to filter packets thought a javascript program.
This is done asynchronously using libuv poll.

## Example

This small example allow one packet every two, and display IP header informations using the pcap binding to decode the payload (payload is provided as a javascript Buffer object by the wrapper, and this is what pcap library handle too)
```js
var nfq = require('nfqueue');
var IPv4 = require('pcap/decode/ipv4');
var counter = 0;

nfq.createQueueHandler(1, function(nfpacket) {
  console.log("-- packet received --");
  console.log(JSON.stringify(nfpacket.info, null, 2));

  // Decode the raw payload using pcap library
  var packet = new IPv4().decode(nfpacket.payload, 0);
  // Protocol numbers, for example: 1 - ICMP, 6 - TCP, 17 - UDP
  console.log(
    "src=" + packet.saddr + ", dst=" + packet.daddr
    + ", proto=" + packet.protocol
  );

  // Set packet verdict. Second parameter set the packet mark.
  nfpacket.setVerdict((counter++ % 2) ? nfq.NF_DROP : nfq.NF_ACCEPT);

  // Or modify packet and set updated payload
  // nfpacket.setVerdict(nfq.NF_ACCEPT, null, nfpacket.payload);
});
```
For an icmp packet, and a nfqueuing in INPUT chain of filter table, it'll output something looking like :

    packet received
    {
      "len": 84,
      "id": 3,
      "nfmark": 0,
      "indev": 2,
      "physindev": 0,
      "outdev": 0,
      "physoutdev": 0,
      "indev_name": "eth0",
      "physintdev_name": "*",
      "outdev_name": "*",
      "physoutdev_name": "*"
    }
    src=10.33.15.1, dst=10.0.2.15, proto=1

Be careful, you must be root to open nfqueue handles. Here is an iptables command example to add a rule sending icmp to nfqueue #1 :

    sudo iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-num 1

## Requirements
  - Linux kernel >= 2.6.30

## Troubleshooting

### Performance and ENOBUFS (No buffer space available)

With a large number of packets in the queue happens that the queue is destroyed due to a read error from the socket

```sh
recvfrom(20, 0x7fffab1d5b70, 65535, 0, 0, 0) = -1 ENOBUFS (No buffer space available)
```
recv() may return -1 and errno is set to ENOBUFS in case that your application is not fast enough to retrieve the packets from the kernel.

By default to avoid queue destroy we use socket option NETLINK_NO_ENOBUFS, it allows ignore packets instead destroy socket with error.
https://patchwork.ozlabs.org/patch/24919/

To avoid packet loss you may increase default socket buffer size up to your need when create queue.
```js
nfq.createQueueHandler(1, 67108864, function() {});
```
Default socket buffer size: 65535.

To improve your libnetfilter_queue application in terms of performance, you may consider the following tweaks:

- increase the default socket buffer size.
set nice value of your process to -20 (maximum priority).
- set the CPU affinity of your process to a spare core that is not used to handle NIC interruptions.
- use --queue-balance option in NFQUEUE target for multi-threaded apps (it requires Linux kernel >= 2.6.31).

http://www.netfilter.org/projects/libnetfilter_queue/doxygen/index.html

## Author and license

Copyright (C) 2014  Anthony Hinsinger

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
