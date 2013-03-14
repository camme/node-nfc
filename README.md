node-nfc
========

A first try at binding libnfc to node. This project is right now not good enough to use. It is also my first real C++ module so dont use it in production. Feel free to contribute.

## Current release
This version only exposes an event that is triggered when a NFC tag is on the reader.

If you still want to try it, here is how it works:


    var nfc = require('nfc').nfc;
    var n = new nfc();

    n.on('uid', function(uid) {
        console.log('UID:', uid);
    });

    n.start();
    
## Installation

To install it, use npm:

    npm install nfc
    
Or to compile it yourself, make sure you have node-gyp

    node-gyp configure
    node-gyp build

## Prerequisites

In order to use the module you need to install libnfc and libusb. Read more about [libnfc here](http://nfc-tools.org/index.php?title=Libnfc)

## License 

(The MIT License)

Copyright (c) 2011 Camilo Tapia &lt;camilo.tapia@gmail.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.