var nfc  = require('./index').nfc
  , util = require('util')
  , version = nfc.version()
  , devices = nfc.scan()
  ;

console.log('version: ' + util.inspect(version, { depth: null }));
console.log('devices: ' + util.inspect(devices, { depth: null }));

var read = function(deviceID) {
  console.log('');
  console.log(new nfc.NFC().on('read', function(tag) {
    console.log(util.inspect(tag, { depth: null }));
    if ((!!tag.data) && (!!tag.offset)) console.log(util.inspect(nfc.parse(tag.data.slice(tag.offset)), { depth: null }));

    if (--count === 0) process.exit(0);
  }).on('error', function(err) {
    console.log(util.inspect(err, { depth: null }));
  }).start(deviceID));

  count++;
};

var count = 0;
for (var deviceID in devices) read(deviceID);
if (count === 0) process.exit(0);
