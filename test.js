var nfc  = require('./index').nfc
  , util = require('util')
  , version = nfc.version()
  , devices = nfc.scan()
  ;

console.log('version: ' + util.inspect(version, { depth: null }));
console.log('devices: ' + util.inspect(devices, { depth: null }));

function read(deviceID) {
  console.log('');
  var nfcdev = new nfc.NFC();

  nfcdev.on('read', function(tag) {
    console.log(util.inspect(tag, { depth: null }));
    if ((!!tag.data) && (!!tag.offset)) console.log(util.inspect(nfc.parse(tag.data.slice(tag.offset)), { depth: null }));
    nfcdev.stop();
  });

  nfcdev.on('error', function(err) {
    console.log(util.inspect(err, { depth: null }));
  });

  nfcdev.on('stopped', function() {
    console.log('stopped');
  });

  console.log(nfcdev.start(deviceID));
}

for (var deviceID in devices) read(deviceID);