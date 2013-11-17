#include <stdlib.h>
#include <err.h>
#include <nfc/nfc.h>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
using namespace v8;
using namespace node;

namespace {

    void NFCRead(uv_work_t* req);
    void AfterNFCRead(uv_work_t* req);

    struct NFC: ObjectWrap {
        static Handle<Value> New(const Arguments& args);
        static Handle<Value> Start(const Arguments& args);
    };

    Handle<Value> NFC::New(const Arguments& args) {
        HandleScope scope;
        assert(args.IsConstructCall());
        NFC* self = new NFC();
        self->Wrap(args.This());
        return scope.Close(args.This());
    }

    struct Baton {
        nfc_device *pnd;
        nfc_target nt;
        nfc_context *context;
        Persistent<Function> callback;
        bool error;
    };

    Handle<Value> NFC::Start(const Arguments& args) {

        HandleScope scope;

        Baton* baton = new Baton();

        nfc_device *pnd;
        nfc_target nt;
        nfc_context *context;
        nfc_init(&context);

        pnd = nfc_open(context, NULL);

        baton->pnd = pnd;
        baton->context = context;
        baton->nt = nt;

        Handle<Function> cb = Handle<Function>::Cast(args.This());

        baton->callback = Persistent<Function>::New(cb);

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
        uv_queue_work(uv_default_loop(), req, NFCRead, (uv_after_work_cb)AfterNFCRead);

        return Undefined();

    }

    void Loop(Baton *baton) {

        HandleScope scope;

        uv_work_t *req = new uv_work_t();
        req->data = baton;
        uv_queue_work(uv_default_loop(), req, NFCRead, (uv_after_work_cb)AfterNFCRead);

        //int status = uv_queue_work(uv_default_loop(), req, NFCRead, AfterNFCRead);
    }

    void NFCRead(uv_work_t* req) {

        Baton* baton = static_cast<Baton*>(req->data);

        const nfc_modulation nmMifare = {
            .nmt = NMT_ISO14443A,
            .nbr = NBR_106,
        };

        baton->error = true;

        //unsigned int last_int = 0;
        if (nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) > 0) {
            baton->error = false;
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

        if (!baton->error) {

            int length = baton->nt.nti.nai.szUidLen;
            uint8_t* rawData = baton->nt.nti.nai.abtUid;
            //char buffer [length];
            //sprintf(buffer, "%02x %02x %02x %02x", rawData[0], rawData[1], rawData[2], rawData[3]);

            node::Buffer *bp = node::Buffer::New(length);
            memcpy(node::Buffer::Data(bp), rawData, length);
            v8::Local<v8::Object> globalObj = v8::Context::GetCurrent()->Global();
            v8::Local<v8::Function> bufferConstructor = v8::Local<v8::Function>::Cast(globalObj->Get(v8::String::New("Buffer")));
            v8::Handle<v8::Value> constructorArgs[3] = { bp->handle_, v8::Integer::New(length), v8::Integer::New(0) };
            v8::Local<v8::Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs);

            //SEND
            Handle<Value> argv[2] = {
                String::New("uid"), // event name
                actualBuffer
                    //String::New(buffer)
            };

            MakeCallback(baton->callback, "emit", 2, argv);

        }

        //baton->callback.Dispose();

        delete req;

        Loop(baton);

    }

    extern "C" void init(Handle<Object> target) {
        HandleScope scope;
        Local<FunctionTemplate> t = FunctionTemplate::New(NFC::New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(String::New("NFC"));
        NODE_SET_PROTOTYPE_METHOD(t, "start", NFC::Start);
        target->Set(String::NewSymbol("NFC"), t->GetFunction());
    }

}
