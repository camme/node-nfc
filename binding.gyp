{
  "targets": [ {
      "target_name": "nfc",
      "sources": [ "src/nfc.cc" ],
      "libraries": [ "-lnfc", "-L/usr/local/lib/" ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        ".",
        "/usr/local/include/",
        "/usr/include/node"
      ],
  } ]
}
