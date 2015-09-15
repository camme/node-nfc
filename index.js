var nfc    = require('bindings')('nfc')
  , events = require('events')
  , ndef   = require('ndef')
  ;

var inherits = function(target, source) {
    for (var k in source.prototype) {
        target.prototype[k] = source.prototype[k];
    }
};
inherits(nfc.NFC, events.EventEmitter);

exports.nfc = { version : nfc.version
              , NFC     : nfc.NFC
              };

exports.nfc.parse = function(data) {
  var bytes, i, results, tlv;

  results = [];

  for (i = 0, bytes = data.toJSON(); i < bytes.length; i += tlv.len) {
    tlv = { type: bytes[i++] };
    if ((tlv.type === 0xfe) || (i >= bytes.length)) {
      results.push(tlv);
      break;
    }

    tlv.len = bytes[i++];
    if (tlv.len === 0xff) {
      if ((i + 1) >= bytes.length) break;
      tlv.len = bytes[i++] << 8;
      tlv.len += bytes[i++];
    }
    if ((tlv.len > 0) && ((i + tlv.len) < bytes.length)) tlv.value = bytes.slice(i, i + tlv.len);
    if ((tlv.type === 0x03) && (!!tlv.value)) tlv.ndef = ndef.decodeMessage(tlv.value);
    if (!!tlv.value) tlv.value = ndef.util.bytesToHexString(tlv.value);
    results.push(tlv);
  }

  return results;
};

exports.nfc.scan = function() {
  var device, devices, i, info, j, k, kv, mod, mods, prop, props, protocol, results, speeds, v, x;

  results = {};

  devices = nfc.scan();
  for (device in devices) if (devices.hasOwnProperty(device)) {
    props = devices[device].info.split('\n');
    info = {};
    for (i = 0; i < props.length; i++) {
      prop = props[i].trim();
      if (prop === '') continue;

      x = prop.indexOf(':');
      if (x < 1) {
        info[i] = prop;
        continue;
      }

      k = prop.substring(0, x);
      v = prop.substring(x + 1).trim();
      if (v.indexOf(')') === -1) {
        info[k] = v;
        continue;
      }

      kv = v.split('), ');
      mods = {};
      for (j = 0; j < kv.length; j++) {
        mod = kv[j].trim();
        if (mod === '') continue;

        x = mod.indexOf(' (');
        if (x < 1) {
          mods[j] = mod;
          continue;
        }
        protocol = mod.substring(0, x);
        speeds = mod.substring(x + 2).trim();
        if (speeds.indexOf(')') === (speeds.length - 1)) speeds = speeds.substring(0, speeds.length - 1);
        mods[protocol] = speeds.split(', ');
      }

      info[k] = mods;
    }

    results[device] = { name: devices[device].name, info: info };
  }

  return results;
};
