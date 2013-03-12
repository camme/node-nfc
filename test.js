var nfc = require('./index').nfc;

var n = new nfc();

//setInterval(function() {
    //console.log('NON BLOCK');
//}, 1000);

n.on('uid', function(uid) {
    console.log('UID:', uid);
});

n.start();



//nfc();

