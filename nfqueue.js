/*

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

*/

var binding = require('./build/Release/nfqueue');

var NFQueue = function() {
  this.opened = false;
  this.bindings = new binding.NFQueue();
};


NFQueue.prototype.open = function(number) {
  // the javascript Buffer to pass packet payload
  this.buf = new Buffer(65535);
  this.bindings.open(number, this.buf);
  this.opened = true;
};

NFQueue.prototype.run = function(callback) {

  var me = this;

  var packet_callback = function(info) {
    return callback(info, me.buf);
  }

  this.bindings.read(packet_callback);
};

exports.NFQueue = NFQueue;

/* Constant */
var i = 0;
exports.NF_DROP = i++;
exports.NF_ACCEPT = i++;
exports.NF_STOLEN = i++;
exports.NF_QUEUE = i++;
exports.NF_REPEAT = i++;
exports.NF_STOP = i++;
