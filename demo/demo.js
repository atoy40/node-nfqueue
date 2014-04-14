var nfq = require('../nfqueue');
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

console.log("test block");
