#include <stdlib.h>
#include <err.h>
#include <nfc/nfc.h>
#include <v8.h>
#include <node.h>

using namespace v8;
using namespace node;

namespace {

    void NFCRead(uv_work_t* req);
    void AfterNFCRead(uv_work_t* req);

    struct NFC: ObjectWrap {
        Handle<Value> New(const Arguments& args);
        static Handle<Value> Foo(const Arguments& args);
        Handle<Value> Start(const Arguments& args);
    };

    const Arguments *mainArgs;
    NFC* self;

    void print_hex(const uint8_t *pbtData, const size_t szBytes) {

        size_t  szPos;
        for (szPos = 0; szPos < szBytes; szPos++) {
            printf("%02x-", pbtData[szPos]);
        }
        printf("\n");

    }

    int conv_dword_to_int(unsigned char * buf) {
        return (( * (buf + 3)) << 24) + (( * (buf + 2)) << 16) + (( * (buf + 1)) << 8) + ( * (buf + 0));
    }

    Handle<Value> NFC::New(const Arguments& args) {
        HandleScope scope;

        assert(args.IsConstructCall());
        self = new NFC();
        self->Wrap(args.This());

        return scope.Close(args.This());
    }

    struct Baton {
        nfc_device *pnd;
        nfc_target nt;
        nfc_context *context;
        const Arguments *args;
    };

    Handle<Value> NFC::Start(const Arguments& args) {

        printf("START\n");
        HandleScope scope;

        mainArgs = &args;
        Baton* baton = new Baton();

        nfc_device *pnd;
        nfc_target nt;
        nfc_context *context;
        nfc_init(&context);

        pnd = nfc_open(context, NULL);

        printf("2\n");
        baton->pnd = pnd;
        baton->context = context;
        baton->nt = nt;
        baton->args = &args;

        nfc_init(&baton->context);

        if (baton->pnd == NULL) {
            warnx("ERROR: %s", "Unable to open NFC device.");
            //return Undefined();
        }
        if (nfc_initiator_init(baton->pnd) < 0) {
            nfc_perror(baton->pnd, "nfc_initiator_init");
            //return Undefined();
        }

        uv_work_t *req = new uv_work_t();
        req->data = baton;

        //int status = uv_queue_work(uv_default_loop(), req, NFCRead, AfterNFCRead);
        uv_queue_work(uv_default_loop(), req, NFCRead, AfterNFCRead);

        return Undefined();

    }

    void Loop(Baton *baton) {
        uv_work_t *req = new uv_work_t();
        req->data = baton;
        uv_queue_work(uv_default_loop(), req, NFCRead, AfterNFCRead);
        //int status = uv_queue_work(uv_default_loop(), req, NFCRead, AfterNFCRead);
    }

    void NFCRead(uv_work_t* req) {

        Baton* baton = static_cast<Baton*>(req->data);

        const nfc_modulation nmMifare = {
            .nmt = NMT_ISO14443A,
            .nbr = NBR_106,
        };

        //unsigned int last_int = 0;
        if (nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) > 0) {
            //unsigned int hex_int = conv_dword_to_int(baton->nt.nti.nai.abtUid);
            //if (hex_int != last_int) {
            //last_int = hex_int;
            //}
        }

        //nfc_close(pnd);
        //nfc_exit(context);

    }

    void AfterNFCRead(uv_work_t* req) {

        HandleScope scope;

        Baton* baton = static_cast<Baton*>(req->data);

        print_hex(baton->nt.nti.nai.abtUid, baton->nt.nti.nai.szUidLen);
        printf("STOP\n");

        //SEND
        Handle<Value> argv[2] = {
            String::New("uid"), // event name
            String::New("tjena")
                //nt.nti.nai.abtUid->toString()
                //args[0]->ToString()  // argument
        };

        printf("HH\n");
        MakeCallback(baton->args->This(), "emit", 2, argv);
        printf("II\n");

        delete req;

        Loop(baton);

    }

    Handle<Value> NFC::Foo(const Arguments& args) {
        HandleScope scope;

        Handle<Value> argv[2] = {
            String::New("tjena"),
            args[0]->ToString()
        };

        MakeCallback(args.This(), "foo", 2, argv);

        return Undefined();
    }

    //extern "C" void init(Handle<Object> target) {
        //HandleScope scope;
        //Local<FunctionTemplate> t = FunctionTemplate::New(NFC::New);
        //t->InstanceTemplate()->SetInternalFieldCount(1);
        //t->SetClassName(String::New("NFC"));
        //NODE_SET_PROTOTYPE_METHOD(t, "foo", NFC::Foo);
        //NODE_SET_PROTOTYPE_METHOD(t, "start", NFC::Start);
        //target->Set(String::NewSymbol("NFC"), t->GetFunction());
    //}

    void init(Handle<Object> exports) {
        exports->Set(String::NewSymbol("nfc"), FunctionTemplate::New(NFC.New)->GetFunction());
    }

    NODE_MODULE(nfc, init);


}
