node-nfqueue
============

This is a node.js binding to the linux netfilter NFQUEUE. It allows to filter packets thought a javascript program.
This is done asynchronously using libuv poll.

## Example

This small example allow one packet every two, and display IP header informations using the pcap binding to decode the payload (payload is provided as a javascript Buffer object by the wrapper, and this is what pcap library handle too)

    var nfq = require('nfqueue');
    var pcap = require('pcap');
    
    var counter = 0;

    nfq.createQueueHandler(1, run(function(nfpacket) {
      console.log("packet received");
      console.log(JSON.stringify(nfpacket.info, null, 2));
    
      // decode the raw payload using pcap library
      var packet = pcap.decode.ip(nfpacket.payload, 0);
      console.log(" ip src=" + packet.saddr);
      console.log(" ip dst=" + packet.daddr);
      console.log(" ip proto=" + packet.protocol_name);
    
      // set packet verdict. Second parameter set the packet mark.
      nfpacket.setVerdict((counter++ % 2) ? nfq.NF_DROP : nfq.NF_ACCEPT);
    });

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
     ip src=192.168.1.136
     ip dst=192.168.1.155
     ip proto=ICMP

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
