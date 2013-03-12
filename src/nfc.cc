#include <stdlib.h>
#include <err.h>
#include <nfc/nfc.h>
#include <v8.h>
#include <node.h>

using namespace v8;
using namespace node;

Handle<Value> NFCRead(const Arguments& args) {

    HandleScope scope;

    nfc_device *pnd;
    nfc_target nt;
    nfc_context *context;
    nfc_init(&context);

    pnd = nfc_open(context, NULL);

    if (pnd == NULL) {
        warnx("ERROR: %s", "Unable to open NFC device.");
        return Undefined();
    }
    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        return Undefined();
    }

    const nfc_modulation nmMifare = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106,
    };

    unsigned int last_int = 0;

    while(true) {

        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0) {

            //unsigned int hexint = conv_dword_to_int(nt.nti.nai.abtUid);
            unsigned int hex_int = (( * (nt.nti.nai.abtUid + 3)) << 24) +
                (( * (nt.nti.nai.abtUid + 2)) << 16) +
                (( * (nt.nti.nai.abtUid + 1)) << 8) +
                ( * (nt.nti.nai.abtUid + 0));

            if (hex_int != last_int) {

                //print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
                last_int = hex_int;

                // SEND
                Handle<Value> argv[2] = {
                    String::New("uid"), // event name
                    //nt.nti.nai.abtUid->toString()
                    args[0]->ToString()  // argument
                };
                MakeCallback(args.This(), "emit", 2, argv);

            }
        }

    }

    nfc_close(pnd);
    nfc_exit(context);

    return Undefined();

}

void print_hex(const uint8_t *pbtData, const size_t szBytes) {
    size_t  szPos;
    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }
    printf("\n");
}

int conv_dword_to_int(unsigned char * buf) {
    return (( * (buf + 3)) << 24) +
        (( * (buf + 2)) << 16) +
        (( * (buf + 1)) << 8) +
        ( * (buf + 0));
}

void Init(Handle<Object> exports) {
    exports->Set(String::NewSymbol("init"), FunctionTemplate::New(NFCRead)->GetFunction());
}

NODE_MODULE(nfc, Init)


