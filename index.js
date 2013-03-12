var NFC = require(__dirname + '/build/Release/nfc').init;
var events = require('events');

inherits(NFC, events.EventEmitter);
exports.nfc = NFC;

// extend prototype
function inherits(target, source) {
    for (var k in source.prototype) {
        target.prototype[k] = source.prototype[k];
    }
}
