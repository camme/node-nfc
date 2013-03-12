var nfc = require('./index').nfc;

var n = new nfc();

n.on('uid', function(uid) {
    console.log('UID:', uid);
});

n.start();


