var nfc = require('./index').nfc;

var n = new nfc();

setInterval(function() {
    console.log('tjena');
}, 1000);

nfc.on('uid', function(uid) {
    console.log('UID:', uid);
});



//nfc();

