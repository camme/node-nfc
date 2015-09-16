#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <nfc/nfc.h>
#include <nan.h>
#include "mifare.h"

using namespace v8;

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

    class NFC: public Nan::ObjectWrap {
      public:
        static NAN_METHOD(New);
        static NAN_METHOD(Start);
        static NAN_METHOD(Stop);
    };

    struct Baton {
        nfc_device *pnd;
        nfc_target nt;
        nfc_context *context;
        Local<Object> self;
        bool error;
    };


    class NFCReadWorker : public Nan::AsyncProgressWorker {
      public:
        NFCReadWorker(Baton *baton)
            : Nan::AsyncProgressWorker(new Nan::Callback(baton->self.As<Function>())), baton(baton) {
                SaveToPersistent("self", baton->self);
                run = true;
        }

        ~NFCReadWorker() {
            delete callback; //For some reason HandleProgressCallback only fires while callback exists.
            nfc_close(baton->pnd);
            nfc_exit(baton->context);
        }

        void HandleOKCallback() {
            Local<Value> argv = Nan::New("stopped").ToLocalChecked();

            Local<Object> self = GetFromPersistent("self").As<Object>();
            Nan::MakeCallback(self, "emit", 1, &argv);
        }

        void HandleErrorCallback() {
            Local<Value> argv[1];
            argv[0] = Nan::New("error").ToLocalChecked();
            argv[1] = Nan::Error(AsyncProgressWorker::ErrorMessage());

            Local<Object> self = GetFromPersistent("self").As<Object>();
            Nan::MakeCallback(self, "emit", 2, argv);
            HandleOKCallback();
        }

        void Execute(const AsyncProgressWorker::ExecutionProgress& progress) {
            while(run) {
                if(nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) <= 0) {
                    AsyncProgressWorker::SetErrorMessage("An error occured while selecting passive NFC target.");
                } else {
                    busy = true;
                    progress.Send((const char *)&busy, sizeof(busy));
                    int timeout = 500;
                    while(busy && --timeout != 0) {
                        usleep(10 * 1000);
                    }
                    if(timeout <= 0) {
                        run = false;
                    }
                }
            }
        }

        #define MAX_DEVICE_COUNT 16
        #define MAX_FRAME_LENGTH 264

        void HandleProgressCallback(const char *unused1, size_t unused2) {
            Nan::HandleScope scope;
            unsigned long cc, n;
            char *bp, result[BUFSIZ];
            const char *sp;
            Local<Object> object = Nan::New<Object>();
            object->Set(Nan::New("deviceID").ToLocalChecked(), Nan::New(nfc_device_get_connstring(baton->pnd)).ToLocalChecked());
            object->Set(Nan::New("name").ToLocalChecked(), Nan::New(nfc_device_get_name(baton->pnd)).ToLocalChecked());

            cc = baton->nt.nti.nai.szUidLen;
            if (cc > sizeof baton->nt.nti.nai.abtUid) cc = sizeof baton->nt.nti.nai.abtUid;
            char uid[3 * sizeof baton->nt.nti.nai.abtUid];
            bzero(uid, sizeof uid);

            for (n = 0, bp = uid, sp = ""; n < cc; n++, bp += strlen(bp), sp = ":") {
                snprintf(bp, sizeof uid - (bp - uid), "%s%02x", sp, baton->nt.nti.nai.abtUid[n]);
            }
            object->Set(Nan::New("uid").ToLocalChecked(), Nan::New(uid).ToLocalChecked());
            object->Set(Nan::New("type").ToLocalChecked(), Nan::New<Int32>(baton->nt.nti.nai.abtAtqa[1]));

            switch (baton->nt.nti.nai.abtAtqa[1]) {
                case 0x04:
                {
                    object->Set(Nan::New("tag").ToLocalChecked(), Nan::New("mifare-classic").ToLocalChecked());

                    // size guessing logic from nfc-mfclassic.c
                    uint8_t uiBlocks =   ((baton->nt.nti.nai.abtAtqa[1] & 0x02) == 0x02) ? 0xff    //  4Kb
                                       : ((baton->nt.nti.nai.btSak & 0x01) == 0x01)      ? 0x13    // 320b
                                       :                                                   0x3f;   //  1Kb/2Kb
                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, false) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
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
                                object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
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
                        object->Set(Nan::New("error").ToLocalChecked(), Nan::Error("unable to reselect tag"));
                        break;
                    }

                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, true) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
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
                                object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
                                break;
                            }
                        }

                        command[0] = MC_READ;
                        command[1] = cnt;
                        res = nfc_initiator_transceive_bytes(baton->pnd, command, 2, dp, 16, -1);
                        if (res >= 0) continue;

                        if (res != NFC_ERFTRANS) {
                            snprintf(result, sizeof result, "nfc_initiator_transceive_bytes: %s", nfc_strerror(baton->pnd));
                            object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
                        }
                        break;
                    }
                    if (cnt >= 0) break;

                    object->Set(Nan::New("data").ToLocalChecked(), Nan::CopyBuffer((char *)&data, len).ToLocalChecked());

                    object->Set(Nan::New("offset").ToLocalChecked(), Nan::New<Int32>(16 * 4));
                    break;
                }

                case 0x44:
                {
                    object->Set(Nan::New("tag").ToLocalChecked(), Nan::New("mifare-ultralight").ToLocalChecked());

                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, true) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
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
                            object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(result));
                        }
                        break;
                    }
                    if (n < cc) break;

                    object->Set(Nan::New("data").ToLocalChecked(), Nan::CopyBuffer((char*)data, len).ToLocalChecked());

                    object->Set(Nan::New("offset").ToLocalChecked(), Nan::New<Int32>(16));
                    break;
                }

                default:
                    break;
            }

            busy = false;

            Local<Object> self = GetFromPersistent("self").As<Object>();
            run = !self->Get(Nan::New("_abort").ToLocalChecked())->IsTrue();

            Local<Value> argv[2];
            argv[0] = Nan::New("read").ToLocalChecked();
            argv[1] = object;
            
            Nan::MakeCallback(self, "emit", 2, argv);
        }

      private:
        Baton *baton;
        bool busy;
        bool run;
    };


    NAN_METHOD(NFC::New) {
        Nan::HandleScope scope;
        assert(info.IsConstructCall());
        NFC* self = new NFC();
        self->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }

    NAN_METHOD(NFC::Stop) {
        Nan::HandleScope scope;
        if(info.This()->IsObject()) {
            info.This()->Set(Nan::New("_abort").ToLocalChecked(), Nan::New<Boolean>(true));
        }
        info.GetReturnValue().Set(info.This());
    }

    NAN_METHOD(NFC::Start) {
        Nan::HandleScope scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return Nan::ThrowError("unable to init libfnc (malloc).");

        nfc_device *pnd;
        if (info.Length() > 0) {
            if (!info[0]->IsString()) {
                nfc_exit(context);
                return Nan::ThrowError("deviceID parameter is not a string");
            }
            nfc_connstring connstring;
            String::Utf8Value device(info[0]->ToString());
            snprintf(connstring, sizeof connstring, "%s", *device);

            pnd = nfc_open(context, connstring);
        } else {
            pnd = nfc_open(context, NULL);
        }
        if (pnd == NULL) {
            nfc_exit(context);
            return Nan::ThrowError("unable open NFC device");
        }

        char result[BUFSIZ];
        if (nfc_initiator_init(pnd) < 0) {
            snprintf(result, sizeof result, "nfc_initiator_init: %s", nfc_strerror(pnd));
            nfc_close(pnd);
            nfc_exit(context);
            return Nan::ThrowError(result);
        }

        Baton* baton = new Baton();
        baton->context = context;
        baton->pnd = pnd;

        baton->self = info.This();

        NFCReadWorker* readWorker = new NFCReadWorker(baton);
        Nan::AsyncQueueWorker(readWorker);

        Local<Object> object = Nan::New<Object>();
        object->Set(Nan::New("deviceID").ToLocalChecked(), Nan::New(nfc_device_get_connstring(baton->pnd)).ToLocalChecked());
        object->Set(Nan::New("name").ToLocalChecked(), Nan::New(nfc_device_get_name(baton->pnd)).ToLocalChecked());

        info.GetReturnValue().Set(object);
    }

    NAN_METHOD(Scan) {
        Nan::HandleScope scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return Nan::ThrowError("unable to init libfnc (malloc).");

        Local<Object> object = Nan::New<Object>();

        nfc_connstring connstrings[MAX_DEVICE_COUNT];
        size_t i, n = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);
        for (i = 0; i < n; i++) {
            Local<Object> entry = Nan::New<Object>();
            nfc_device *pnd = nfc_open(context, connstrings[i]);
            if (pnd == NULL) continue;

            entry->Set(Nan::New("name").ToLocalChecked(), Nan::New(nfc_device_get_name(pnd)).ToLocalChecked());

            char *info;
            if (nfc_device_get_information_about(pnd, &info) >= 0) {
                entry->Set(Nan::New("info").ToLocalChecked(), Nan::New(info).ToLocalChecked());
                nfc_free(info);
            } else {
                entry->Set(Nan::New("info").ToLocalChecked(), Nan::New("").ToLocalChecked());
            }
            object->Set(Nan::New(nfc_device_get_connstring(pnd)).ToLocalChecked(), entry);

            nfc_close(pnd);
        }

        nfc_exit(context);

        info.GetReturnValue().Set(object);
    }

    NAN_METHOD(Version) {
        Nan::HandleScope       scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return Nan::ThrowError("unable to init libnfc (malloc).");

        Local<Object> object = Nan::New<Object>();
        object->Set(Nan::New("name").ToLocalChecked(), Nan::New("libnfc").ToLocalChecked());
        object->Set(Nan::New("version").ToLocalChecked(), Nan::New(nfc_version()).ToLocalChecked());

        nfc_exit(context);

        info.GetReturnValue().Set(object);
    }

    NAN_MODULE_INIT(init) {
        Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(NFC::New);
        tpl->SetClassName(Nan::New("NFC").ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        SetPrototypeMethod(tpl, "start", NFC::Start);
        SetPrototypeMethod(tpl, "stop", NFC::Stop);

        Nan::Export(target, "version", Version);
        Nan::Export(target, "scan", Scan);
        Nan::Set(target, Nan::New("NFC").ToLocalChecked(), tpl->GetFunction());
    };
}

NODE_MODULE(nfc, init)
