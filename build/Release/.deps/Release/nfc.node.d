cmd_Release/nfc.node := ln -f "Release/obj.target/nfc.node" "Release/nfc.node" 2>/dev/null || (rm -rf "Release/nfc.node" && cp -af "Release/obj.target/nfc.node" "Release/nfc.node")
