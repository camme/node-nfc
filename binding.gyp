{
  "targets": [ {
      "target_name": "nfc",
      "sources": [ "src/nfc.cc" ],
      "libraries": [ "-lnfc" ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")","."
      ],
  } ]
}
