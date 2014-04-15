var nfq = require('../nfqueue');
var pcap = require('pcap');

var q = new nfq.NFQueue();
var counter = 0;

q.open(1);

q.run(function(nfpacket) {
  console.log(JSON.stringify(nfpacket.info, null, 2));

  var packet = pcap.decode.ip(nfpacket.payload, 0);
  console.log(" ip src=" + packet.saddr);
  console.log(" ip dst=" + packet.daddr);
  console.log(" ip proto=" + packet.protocol_name);

  nfpacket.setVerdict((counter++ % 2) ? nfq.NF_DROP : nfq.NF_ACCEPT);
});
