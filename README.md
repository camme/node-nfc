node-nfc
========
A binding from libnfc to node.
At present,
only reading is supported.

## Installation

### Step 1: Prerequisites
In order to use the module you need to install libnfc and libusb.
Read more about [libnfc here](http://nfc-tools.org/index.php?title=Libnfc).

On Linux, you want:

    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get install libusb-dev libnfc

On MacOS X, you want:

    brew update
    brew doctor
    brew install libusb-compat libnfc

### Step 2: Installation

To install it, use npm:

    npm install nfc
    
Or, to compile it yourself, make sure you have node-gyp:

    node-gyp configure
    node-gyp build

### NPM errors

- An error of **missing nfc.h** indicates that libnfc isn't installed correctly.

### Runtime errors

- An error of **Unable to claim USB interface (Permission denied)**
indicates that another process has the interface. On MacOS X you can try:

    $ sudo killall pcscd


## Initialization and Information

    var nfc  = require('nfc').nfc
      , util = require('util')
      ;

    console.log('nfc.version(): ' + util.inspect(nfc.version(), { depth: null }));
        // { name: 'libfnc', version: '1.7.0' }

    console.log('nfc.scan(): ' + util.inspect(nfc.scan(), { depth: null }));
        // { 'pn53x_usb:160:012': { name: 'SCM Micro / SCL3711-NFC&RW', info: { chip: 'PN533 v2.7', ... } } }

## Reading

    var device = new nfc.NFC();
    device.on('read', function(tag) {
        // { deviceID: '...', name: '...', uid: '...', type: 0x04 (Mifare Classic) or 0x44 (Mifare Ultralight) }

        if ((!!tag.data) && (!!tag.offset)) console.log(util.inspect(nfc.parse(tag.data.slice(tag.offset)), { depth: null }));
    }).on('error', function(err) {
        // handle background error;
    }).start();
    // optionally the start function may include the deviceID (e.g., 'pn53x_usb:160:012')

## And an extra thanks to...

[jeroenvollenbrock](https://github.com/jeroenvollenbrock) for the huge update he made to this project!

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
