#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <nfc/nfc.h>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include "mifare.h"

using namespace v8;
using namespace node;

static const nfc_modulation nmMifare = {
  NMT_ISO14443A,
  NBR_106,
};

static uint8_t keys[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
  0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
  0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};
static size_t num_keys = sizeof(keys) / 6;


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

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return ThrowException(Exception::Error(String::New("unable to init libfnc (malloc).")));

        nfc_device *pnd;
        if (args.Length() > 0) {
            if (!args[0]->IsString()) {
                nfc_exit(context);
                return ThrowException(Exception::Error(String::New("deviceID parameter is not a string")));
            }
            nfc_connstring connstring;
            String::Utf8Value device(args[0]->ToString());
            snprintf(connstring, sizeof connstring, "%s", *device);

            pnd = nfc_open(context, connstring);
        } else {
            pnd = nfc_open(context, NULL);
        }
        if (pnd == NULL) {
            nfc_exit(context);
            return ThrowException(Exception::Error(String::New("unable open NFC device")));
        }

        char result[BUFSIZ];
        if (nfc_initiator_init(pnd) < 0) {
            snprintf(result, sizeof result, "nfc_initiator_init: %s", nfc_strerror(pnd));
            nfc_close(pnd);
            nfc_exit(context);
            return ThrowException(Exception::Error(String::New(result)));
        }

        Baton* baton = new Baton();
        baton->context = context;
        baton->pnd = pnd;

        Handle<Function> cb = Handle<Function>::Cast(args.This());
        baton->callback = Persistent<Function>::New(cb);

        uv_work_t *req = new uv_work_t();
        req->data = baton;

        uv_queue_work(uv_default_loop(), req, NFCRead, (uv_after_work_cb)AfterNFCRead);

        Local<Object> object = Object::New();
        object->Set(NODE_PSYMBOL("deviceID"), String::New(nfc_device_get_connstring(baton->pnd)));
        object->Set(NODE_PSYMBOL("name"), String::New(nfc_device_get_name(baton->pnd)));
        return scope.Close(object);
    }

    void Loop(Baton *baton) {

        HandleScope scope;

        uv_work_t *req = new uv_work_t();
        req->data = baton;
        uv_queue_work(uv_default_loop(), req, NFCRead, (uv_after_work_cb)AfterNFCRead);
    }

    void NFCRead(uv_work_t* req) {
        Baton* baton = static_cast<Baton*>(req->data);

        baton->error = nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) <= 0;
    }

#define MAX_DEVICE_COUNT 16
#define MAX_FRAME_LENGTH 264

    void AfterNFCRead(uv_work_t* req) {
        HandleScope scope;

        Baton* baton = static_cast<Baton*>(req->data);

        if (!baton->error) {
            unsigned long cc, n;
            char *bp, result[BUFSIZ];
            const char *sp;
            Handle<Value> argv[2];

            Local<Object> object = Object::New();
            object->Set(NODE_PSYMBOL("deviceID"), String::New(nfc_device_get_connstring(baton->pnd)));
            object->Set(NODE_PSYMBOL("name"), String::New(nfc_device_get_name(baton->pnd)));

            cc = baton->nt.nti.nai.szUidLen;
            if (cc > sizeof baton->nt.nti.nai.abtUid) cc = sizeof baton->nt.nti.nai.abtUid;
            char uid[3 * sizeof baton->nt.nti.nai.abtUid];
            bzero(uid, sizeof uid);

            for (n = 0, bp = uid, sp = ""; n < cc; n++, bp += strlen(bp), sp = ":") {
                snprintf(bp, sizeof uid - (bp - uid), "%s%02x", sp, baton->nt.nti.nai.abtUid[n]);
            }
            object->Set(NODE_PSYMBOL("uid"), String::New(uid));
            object->Set(NODE_PSYMBOL("type"), Integer::New(baton->nt.nti.nai.abtAtqa[1]));

            switch (baton->nt.nti.nai.abtAtqa[1]) {
                case 0x04:
                {
                    object->Set(NODE_PSYMBOL("tag"), String::New("mifare-classic"));

                    // size guessing logic from nfc-mfclassic.c
                    uint8_t uiBlocks =   ((baton->nt.nti.nai.abtAtqa[1] & 0x02) == 0x02) ? 0xff    //  4Kb
                                       : ((baton->nt.nti.nai.btSak & 0x01) == 0x01)      ? 0x13    // 320b
                                       :                                                   0x3f;   //  1Kb/2Kb
                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, false) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                        break;
                    }
                    uint8_t abtRats[2] = { 0xe0, 0x50 };
                    uint8_t abtRx[MAX_FRAME_LENGTH];
                    int res = nfc_initiator_transceive_bytes(baton->pnd, abtRats, sizeof abtRats, abtRx, sizeof abtRx, 0);
                    if (res > 0) {
                        int flip;

                        for (flip = 0; flip < 2; flip++) {
                            if (nfc_device_set_property_bool(baton->pnd, NP_ACTIVATE_FIELD, flip > 0) < 0) {
                                snprintf(result, sizeof result, "nfc_device_set_property_bool activateField=%s: %s",
                                         flip > 0 ? "true" : "false", nfc_strerror(baton->pnd));
                                object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                                break;
                            }
                        }
                        if (flip != 2) break;

                        if ((res >= 10)
                              && (abtRx[5] == 0xc1)
                              && (abtRx[6] == 0x05)
                              && (abtRx[7] == 0x2f)
                              && (abtRx[8] == 0x2f)
                              && ((baton->nt.nti.nai.abtAtqa[1] & 0x02) == 0x00)) uiBlocks = 0x7f;
                    }
                    if (nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) <= 0) {
                        object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New("unable to reselect tag")));
                        break;
                    }

                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, true) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                        break;
                    }

                    int cnt, len;
                    uint8_t command[MAX_FRAME_LENGTH], data[4 * 1024], *dp;
                    len = (uiBlocks + 1) * 16;
                    if (((unsigned long) len) > sizeof data) len = sizeof data;
                    for (cnt = uiBlocks, dp = data + len - 16;
                             cnt >= 0;
                             cnt--, dp -= 16) {
                        if (((cnt + 1) % (cnt < 128 ? 4 : 16)) == 0) {
                            size_t key_index;
                            struct mifare_param_auth auth_params;
                            for (key_index = 0; key_index < num_keys; key_index++) {
                                bzero(command, sizeof command);
                                command[0] = MC_AUTH_B;
                                command[1] = cnt;

                                bzero(&auth_params, sizeof auth_params);
                                memcpy(auth_params.abtKey, (uint8_t *) keys + (key_index * 6),
                                       sizeof auth_params.abtKey);
                                memcpy(auth_params.abtAuthUid, baton->nt.nti.nai.abtUid + baton->nt.nti.nai.szUidLen - 4,
                                       sizeof auth_params.abtAuthUid);
                                memcpy(command + 2, &auth_params, sizeof auth_params);

                                res = nfc_initiator_transceive_bytes(baton->pnd, command, 2 + sizeof auth_params, abtRx,
                                                                     sizeof abtRx, -1);
                                if (res >= 0) break;
                            }
                            if (key_index >= num_keys) {
                                snprintf(result, sizeof result, "nfc_initiator_transceive_bytes: %s", nfc_strerror(baton->pnd));
                                object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                                break;
                            }
                        }

                        command[0] = MC_READ;
                        command[1] = cnt;
                        res = nfc_initiator_transceive_bytes(baton->pnd, command, 2, dp, 16, -1);
                        if (res >= 0) continue;

                        if (res != NFC_ERFTRANS) {
                            snprintf(result, sizeof result, "nfc_initiator_transceive_bytes: %s", nfc_strerror(baton->pnd));
                            object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                        }
                        break;
                    }
                    if (cnt >= 0) break;

                    node::Buffer *slowBuffer = node::Buffer::New(len);
                    memcpy(node::Buffer::Data(slowBuffer), &data, len);
                    Local<Object> globalObj = Context::GetCurrent()->Global();
                    Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
                    Handle<Value> constructorArgs[3] = { slowBuffer->handle_, Integer::New(len), Integer::New(0) };
                    object->Set(NODE_PSYMBOL("data"), bufferConstructor->NewInstance(3, constructorArgs));

                    object->Set(NODE_PSYMBOL("offset"), Integer::New(16 * 4));
                    break;
                }

                case 0x44:
                {
                    object->Set(NODE_PSYMBOL("tag"), String::New("mifare-ultralight"));

                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, true) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                        break;
                    }

                    int cnt, len, res;
                    uint8_t command[2], data[16 * 4], *dp;
                    for (n = 0, cc = 0x0f, dp = data, cnt = sizeof data, len = 0;
                             n < cc;
                             n += 4, dp += res, cnt -= res, len += res) {
                        command[0] = MC_READ;
                        command[1] = n;
                        res = nfc_initiator_transceive_bytes(baton->pnd, command, 2, dp, cnt, -1);
                        if (res >= 0) continue;

                        if (res != NFC_ERFTRANS) {
                            snprintf(result, sizeof result, "nfc_initiator_transceive_bytes: %s", nfc_strerror(baton->pnd));
                            object->Set(NODE_PSYMBOL("error"), Exception::Error(String::New(result)));
                        }
                        break;
                    }
                    if (n < cc) break;

                    node::Buffer *slowBuffer = node::Buffer::New(len);
                    memcpy(node::Buffer::Data(slowBuffer), data, len);
                    Local<Object> globalObj = Context::GetCurrent()->Global();
                    Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
                    Handle<Value> constructorArgs[3] = { slowBuffer->handle_, Integer::New(len), Integer::New(0) };
                    object->Set(NODE_PSYMBOL("data"), bufferConstructor->NewInstance(3, constructorArgs));

                    object->Set(NODE_PSYMBOL("offset"), Integer::New(16));
                    break;
                }

                default:
                    break;
            }

            argv[0] = String::New("read");
            argv[1] = object;
            MakeCallback(baton->callback, "emit", sizeof argv / sizeof argv[0], argv);
        }

        delete req;

        Loop(baton);
    }

    Handle<Value> Scan(const Arguments& args) {
        HandleScope       scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return ThrowException(Exception::Error(String::New("unable to init libfnc (malloc).")));

        Local<Object> object = Object::New();

        nfc_connstring connstrings[MAX_DEVICE_COUNT];
        size_t i, n = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);
        for (i = 0; i < n; i++) {
            Local<Object> entry = Object::New();
            nfc_device *pnd = nfc_open(context, connstrings[i]);
            if (pnd == NULL) continue;

            entry->Set(NODE_PSYMBOL("name"), String::New(nfc_device_get_name(pnd)));

            char *info;
            if (nfc_device_get_information_about(pnd, &info) >= 0) {
                entry->Set(NODE_PSYMBOL("info"), String::New(info));
                nfc_free(info);
            } else {
                entry->Set(NODE_PSYMBOL("info"), String::New(""));
            }
            object->Set(NODE_PSYMBOL(nfc_device_get_connstring(pnd)), entry);

            nfc_close(pnd);
        }

        nfc_exit(context);

        return scope.Close(object);
    }

    Handle<Value> Version(const Arguments& args) {
        HandleScope       scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return ThrowException(Exception::Error(String::New("unable to init libfnc (malloc).")));

        Local<Object> object = Object::New();
        object->Set(NODE_PSYMBOL("name"), String::New("libnfc"));
        object->Set(NODE_PSYMBOL("version"), String::New(nfc_version()));

        nfc_exit(context);

        return scope.Close(object);
    }

    extern "C" void init(Handle<Object> target) {
        HandleScope scope;

        Local<FunctionTemplate> t = FunctionTemplate::New(NFC::New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(String::New("NFC"));
        NODE_SET_PROTOTYPE_METHOD(t, "start", NFC::Start);
        target->Set(String::NewSymbol("NFC"), t->GetFunction());

        target->Set(String::NewSymbol("scan"), FunctionTemplate::New(Scan)->GetFunction());
        target->Set(String::NewSymbol("version"), FunctionTemplate::New(Version)->GetFunction());
    }

}

NODE_MODULE(nfc, init)
