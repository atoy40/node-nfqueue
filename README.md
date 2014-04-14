node-nfqueue
============

This is a node.js binding to the linux netfilter NFQUEUE. It allows to filter packets thought a javascript program.
This is done asynchronously using libuv poll.

## Example

This small example allow one packet every two, and display IP header informations using the pcap binding to decode the payload (payload is a javascript Buffer object)

 var nfq = require('nfqueue');
 var pcap = require('pcap');
 
 var q = new nfq.NFQueue();
 var counter = 0;
 
 q.open(1);
 
 q.run(function(info, payload) {
   console.log("packet received, size=" + info.len);
 
   var packet = pcap.decode.ip(payload, 0);
   console.log(" ip src=" + packet.saddr);
   console.log(" ip dst=" + packet.daddr);
   console.log(" ip proto=" + packet.protocol_name);
 
   return (counter++ % 2) ? nfq.NF_DROP : nfq.NF_ACCEPT;
 });

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
