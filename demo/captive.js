/*
 * This is a very simple captive portal
 * It requires some iptables rules.
 * 1. in a prerouting chain : send packet to the queue
 * 2. in a postrouting chain
 *   - accept and/or nat packet with mark 1
 *   - redirect http packet with mark 0 the local http server and port
 *   - drop others
 */
var nfq = require('../nfqueue');
var pcap = require('pcap');
var http = require('http');
var url = require('url');

var SERVER_HOST="your.linux.router.ip.or.name";
var allows = []; // store allowed clients

// nfqueue handler : set mark to 1 for allowed packet
nfq.createQueueHandler(1, function(nfpacket) {
  console.log("packet received");
  var packet = pcap.decode.ip(nfpacket.payload, 0);
  nfpacket.setVerdict(nfq.NF_ACCEPT, allows.indexOf(packet.saddr) != -1 ? 1 : 0);
});

// http server : open access
http.createServer(function(req, res) {
  var parsedUrl = url.parse(req.url, true);
  res.writeHead(200, {'Content-Type': 'text/html'});

  if (!req.headers.host || req.headers.host.search(SERVER_HOST) == -1) {
    res.write('<html><head><meta HTTP-EQUIV="REFRESH" content="0;url="http://'+SERVER_HOST+'"></head></html>');
  } else if (allows.indexOf(req.connection.remoteAddress) != -1 || (parsedUrl.query && parsedUrl.query.open)) {
    allows.push(req.connection.remoteAddress);
    res.write('<p>You are now allowed to navigate<p>');
  } else {
    res.write('<a href="http://'+SERVER_HOST+'/?open=1">Click here to open access</a>');
  }
  res.end();
}).listen(80);
