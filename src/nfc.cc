#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <nfc/nfc.h>
#include <nan.h>
#include "mifare.h"

using namespace v8;
using namespace std;

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
    bool nfc_initiator_mifare_cmd(nfc_device *pnd, const mifare_cmd mc, const uint8_t ui8Block, mifare_param *pmp)
    {
        uint8_t  abtRx[265];
        size_t  szParamLen;
        uint8_t  abtCmd[265];
        //bool    bEasyFraming;

        abtCmd[0] = mc;               // The MIFARE Classic command
        abtCmd[1] = ui8Block;         // The block address (1K=0x00..0x39, 4K=0x00..0xff)

        switch (mc) {
            // Read and store command have no parameter
            case MC_READ:
            case MC_STORE:
                szParamLen = 0;
                break;

                // Authenticate command
            case MC_AUTH_A:
            case MC_AUTH_B:
                szParamLen = sizeof(struct mifare_param_auth);
                break;

                // Data command
            case MC_WRITE:
                szParamLen = sizeof(struct mifare_param_data);
                break;

                // Value command
            case MC_DECREMENT:
            case MC_INCREMENT:
            case MC_TRANSFER:
                szParamLen = sizeof(struct mifare_param_value);
                break;

                // Please fix your code, you never should reach this statement
            default:
                return false;
        }

        // When available, copy the parameter bytes
        if (szParamLen)
            memcpy(abtCmd + 2, (uint8_t *) pmp, szParamLen);

        // FIXME: Save and restore bEasyFraming
        // bEasyFraming = nfc_device_get_property_bool (pnd, NP_EASY_FRAMING, &bEasyFraming);
        if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true) < 0) {
            nfc_perror(pnd, "nfc_device_set_property_bool");
            return false;
        }
        // Fire the mifare command
        int res;
        if ((res = nfc_initiator_transceive_bytes(pnd, abtCmd, 2 + szParamLen, abtRx, sizeof(abtRx), -1))  < 0) {
            if (res == NFC_ERFTRANS) {
                // "Invalid received frame",  usual means we are
                // authenticated on a sector but the requested MIFARE cmd (read, write)
                // is not permitted by current acces bytes;
                // So there is nothing to do here.
            } else {
                nfc_perror(pnd, "nfc_initiator_transceive_bytes");
            }
            // XXX nfc_device_set_property_bool (pnd, NP_EASY_FRAMING, bEasyFraming);
            return false;
        }
        /* XXX
           if (nfc_device_set_property_bool (pnd, NP_EASY_FRAMING, bEasyFraming) < 0) {
           nfc_perror (pnd, "nfc_device_set_property_bool");
           return false;
           }
           */

        // When we have executed a read command, copy the received bytes into the param
        if (mc == MC_READ) {
            if (res == 16) {
                memcpy(pmp->mpd.abtData, abtRx, 16);
            } else {
                return false;
            }
        }
        // Command succesfully executed
        return true;
    }

    class NFC: public Nan::ObjectWrap {
        public:
            static NAN_METHOD(New);
            static NAN_METHOD(Start);
            static NAN_METHOD(Stop);
            static NAN_METHOD(Write);

            void stop() {
                run = false;
                while(claimed);
                if(pnd) {
                    nfc_abort_command(pnd);
                    nfc_close(pnd);
                    pnd = NULL;
                }
                if(context) {
                    nfc_exit(context);
                    context = NULL;
                }
            }

            nfc_device *pnd;
            nfc_target nt;
            nfc_context *context;
            bool run;
            bool claimed;
    };

    /*
     * Write blocks to NFC card
     * TODO: Refactor with `AsyncProcessWorker`
     */
    NAN_METHOD(NFC::Write) {
        Nan::HandleScope scope;
        Isolate *isolate = info.GetIsolate();

        NFC* baton = ObjectWrap::Unwrap<NFC>(info.This());
        Local<Object> bufferObj    = info[0]->ToObject();
        char *data   = node::Buffer::Data(bufferObj);

        bool write_otp = false;
        bool write_lock = false;
        //bool write_uid = false;

        uint8_t uiBlocks = 0x0f;
        uint8_t uiPages = uiBlocks;
        uint32_t uiBlock = 0;
        uint32_t uiSkippedPages = 0;
        uint32_t uiPagesWritten = 0;
        bool bFailure = false;

        mifare_param mp;        // auth(10 bytes), data(16 bytes), value(4 bytes)
        mifareul_tag mt;        // 4 blocks (64 bytes)

        bzero(&mp, sizeof mp);
        bzero(&mt, sizeof mt);
        memcpy(&mt, data, sizeof mt);

        // TODO: figure out how to fix the error and remove the while loop
        // error   libnfc.driver.pn532_i2c Length checksum mismatch
        // error   libnfc.chip.pn53x       Unexpected PN53x reply!
        while (nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) <= 0){
          printf("Selecting tag...\n");
        }

        switch (baton->nt.nti.nai.abtAtqa[1]) {
            case 0x04:
            {// TODO: Mifare classic
                break;
            }
            case 0x44:
            { // Mifare ultralight
                uiSkippedPages = 2;
                // TODO: only support write 8 pages (2 data blocks) in the first 
                // sector now, extend to support more sectors.
                for (uint32_t page = uiSkippedPages; page < ((uiPages / 4) * 4); page++) {
                    if ((page == 0x2) && (!write_lock)) {
                      uiSkippedPages++;
                      continue;
                    }
                    if ((page == 0x3) && (!write_otp)) {
                      uiSkippedPages++;
                      continue;
                    }
                    // Show if the readout went well
                    if (bFailure) {
                      // When a failure occured we need to redo the anti-collision
                      if (nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) <= 0) {
                        printf("Tag was removed \n");
                        break;
                      }
                      bFailure = false;
                    }
                    // For the Mifare Ultralight, this write command can be used
                    // in compatibility mode, which only actually writes the first
                    // page (4 bytes). The Ultralight-specific Write command only
                    // writes one page at a time.
                    uiBlock = page / 4;
                    memcpy(mp.mpd.abtData, mt.amb[uiBlock].mbd.abtData + ((page % 4) * 4), 4);
                    memset(mp.mpd.abtData + 4, 0, 12);

                    uint8_t i =0;
                    uint8_t *bytes; 
                    for (i=0, bytes=mp.mpd.abtData; i < (sizeof mp.mpd.abtData / sizeof mp.mpd.abtData[0]); i++) {
                      printf("%02x ", bytes[i]);
                    }
                    printf("\n");


                    if (!nfc_initiator_mifare_cmd(baton->pnd, MC_WRITE, page, &mp)) {
                      bFailure = true;
                      printf("Failed at page: %d\n", page);
                    }
                    else
                        uiPagesWritten++;

                }   // For loop for writing pages

                break;
            }
            default:
                ;
        } // switch card type
        Local<Number> ret = Number::New(isolate, uiPagesWritten);
        info.GetReturnValue().Set(ret);
    }

    class NFCCard {
      public:
        NFCCard() {
            deviceID = name = uid = tag = error = NULL;
            type = data_size = offset = 0;
            data = NULL;
        }

        ~NFCCard() {
            delete deviceID;
            delete name;
            delete uid;
            delete tag;
            delete error;
            if(data) delete data;
        }

        void AddToNodeObject(Local<Object> object) {
            if(deviceID) object->Set(Nan::New("deviceID").ToLocalChecked(), Nan::New(deviceID).ToLocalChecked());
            if(name) object->Set(Nan::New("name").ToLocalChecked(), Nan::New(name).ToLocalChecked());
            if(uid) object->Set(Nan::New("uid").ToLocalChecked(), Nan::New(uid).ToLocalChecked());
            if(type) object->Set(Nan::New("type").ToLocalChecked(), Nan::New<Int32>(type));
            if(tag) object->Set(Nan::New("tag").ToLocalChecked(), Nan::New(tag).ToLocalChecked());
            if(error) object->Set(Nan::New("error").ToLocalChecked(), Nan::Error(error));
            if(data) object->Set(Nan::New("data").ToLocalChecked(), Nan::NewBuffer(data, data_size).ToLocalChecked());
            if(offset) object->Set(Nan::New("offset").ToLocalChecked(), Nan::New<Int32>((int32_t)offset));
            data = NULL; //ownership transferred to nodejs
        }

        void SetDeviceID(const char *deviceID) {
            if(this->deviceID) delete this->deviceID;
            this->deviceID = strdup(deviceID);
        }
        void SetName(const char *name) {
            if(this->name) delete this->name;
            this->name = strdup(name);
        }
        void SetUID(const char *uid) {
            if(this->uid) delete this->uid;
            this->uid = strdup(uid);
        }
        void SetType(int32_t type) {
            this->type = type;
        }
        void SetTag(const char *tag) {
            if(this->tag) delete this->tag;
            this->tag = strdup(tag);
        }
        void SetError(const char *error) {
            if(this->error) delete this->error;
            this->error = strdup(error);
        }
        void SetOffset(size_t offset) {
            this->offset = offset;
        }
        void SetData(const uint8_t *data, size_t data_size) {
            if(this->data) free(this->data);
            this->data_size = data_size;
            this->data = (char*)malloc(data_size);
            memcpy(this->data, data, data_size);
        }

      private:
        char        *deviceID;
        char        *name;
        char        *uid;
        int32_t     type;
        char        *tag;
        char        *error;
        size_t      offset;
        size_t      data_size;
        char        *data;
    };

    class NFCReadWorker : public Nan::AsyncProgressWorker {
      public:
        NFCReadWorker(NFC *baton, Local<Object>self)
            : Nan::AsyncProgressWorker(new Nan::Callback(self.As<Function>())), baton(baton) {
                SaveToPersistent("self", self);
                baton->run = true;
        }

        ~NFCReadWorker() {
            delete callback; //For some reason HandleProgressCallback only fires while callback exists.
        }

        void HandleOKCallback() {
            Local<Value> argv = Nan::New("stopped").ToLocalChecked();

            Local<Object> self = GetFromPersistent("self").As<Object>();
            Nan::MakeCallback(self, "emit", 1, &argv);
        }

        void HandleErrorCallback() {
            Local<Value> argv[2];
            argv[0] = Nan::New("error").ToLocalChecked();
            argv[1] = Nan::Error(AsyncProgressWorker::ErrorMessage());

            Local<Object> self = GetFromPersistent("self").As<Object>();
            Nan::MakeCallback(self, "emit", 2, argv);
            HandleOKCallback();
        }

        void Execute(const AsyncProgressWorker::ExecutionProgress& progress) {
            while(baton->run && nfc_initiator_select_passive_target(baton->pnd, nmMifare, NULL, 0, &baton->nt) > 0) {
                baton->claimed = true;
                tag = new NFCCard();
                if(baton->run) ReadTag(tag);
                baton->claimed = false;

                progress.Send(NULL, 0);

                int timeout = 5 * 1000; //5 second timeout
                while(baton->run && tag && --timeout > 0) {
                    usleep(1000);
                }
                if(timeout <= 0) {
                    //unresponsive VM, node was likely killed while this devide was not stopped.
                    baton->stop();
                    baton->run = false;
                    fprintf(stderr, "Node was stopped while some NFC devices where still started.\n");
                }
            }
        }

        #define MAX_DEVICE_COUNT 16
        #define MAX_FRAME_LENGTH 264

        void ReadTag(NFCCard *tag) {
            unsigned long cc, n;
            char *bp, result[BUFSIZ];
            const char *sp;

            tag->SetDeviceID(nfc_device_get_connstring(baton->pnd));
            tag->SetName(nfc_device_get_name(baton->pnd));

            cc = baton->nt.nti.nai.szUidLen;
            if (cc > sizeof baton->nt.nti.nai.abtUid) cc = sizeof baton->nt.nti.nai.abtUid;
            char uid[3 * sizeof baton->nt.nti.nai.abtUid];
            bzero(uid, sizeof uid);

            for (n = 0, bp = uid, sp = ""; n < cc; n++, bp += strlen(bp), sp = ":") {
                snprintf(bp, sizeof uid - (bp - uid), "%s%02x", sp, baton->nt.nti.nai.abtUid[n]);
            }
            tag->SetUID(uid);
            tag->SetType(baton->nt.nti.nai.abtAtqa[1]);

            switch (baton->nt.nti.nai.abtAtqa[1]) {
                case 0x04:
                {
                    tag->SetTag("mifare-classic");

                    // size guessing logic from nfc-mfclassic.c
                    uint8_t uiBlocks =   ((baton->nt.nti.nai.abtAtqa[1] & 0x02) == 0x02) ? 0xff    //  4Kb
                                       : ((baton->nt.nti.nai.btSak & 0x01) == 0x01)      ? 0x13    // 320b
                                       :                                                   0x3f;   //  1Kb/2Kb
                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, false) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        tag->SetError(result);
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
                                tag->SetError(result);
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
                        tag->SetError("unable to reselect tag");
                        break;
                    }

                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, true) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        tag->SetError(result);
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
                                tag->SetError(result);
                                break;
                            }
                        }

                        command[0] = MC_READ;
                        command[1] = cnt;
                        res = nfc_initiator_transceive_bytes(baton->pnd, command, 2, dp, 16, -1);
                        if (res >= 0) continue;

                        if (res != NFC_ERFTRANS) {
                            snprintf(result, sizeof result, "nfc_initiator_transceive_bytes: %s", nfc_strerror(baton->pnd));
                            tag->SetError(result);
                        }
                        break;
                    }
                    if (cnt >= 0) break;

                    tag->SetData(data, len);

                    tag->SetOffset(16 * 4);
                    break;
                }

                case 0x44:
                {
                    tag->SetTag("mifare-ultralight");

                    if (nfc_device_set_property_bool(baton->pnd, NP_EASY_FRAMING, true) < 0) {
                        snprintf(result, sizeof result, "nfc_device_set_property_bool easyFraming=false: %s",
                                 nfc_strerror(baton->pnd));
                        tag->SetError(result);
                        break;
                    }

                    int cnt, len, res;
                    uint8_t command[2], data[16 * 12], *dp;
                    for (n = 0, cc = 0x0f, dp = data, cnt = sizeof data, len = 0;
                             n < cc;
                             n += 4, dp += res, cnt -= res, len += res) {
                        command[0] = MC_READ;
                        command[1] = n;
                        res = nfc_initiator_transceive_bytes(baton->pnd, command, 2, dp, cnt, -1);
                        if (res >= 0) continue;

                        if (res != NFC_ERFTRANS) {
                            snprintf(result, sizeof result, "nfc_initiator_transceive_bytes: %s", nfc_strerror(baton->pnd));
                            tag->SetError(result);
                        }
                        break;
                    }
                    if (n < cc) break;

                    tag->SetData(data, len);

                    tag->SetOffset(16);
                    break;
                }

                default:
                    break;
            }
        }
        
       
        void HandleProgressCallback(const char *_tag, size_t size) {
            Nan::HandleScope scope;

            Local<Object> object = Nan::New<Object>();
            tag->AddToNodeObject(object);
            delete tag;
            tag = NULL;

            Local<Value> argv[2];
            argv[0] = Nan::New("read").ToLocalChecked();
            argv[1] = object;
            
            Local<Object> self = GetFromPersistent("self").As<Object>();
            Nan::MakeCallback(self, "emit", 2, argv);
        }

      private:
        NFC *baton;
        NFCCard *tag;
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
        NFC* nfc = ObjectWrap::Unwrap<NFC>(info.This());
        nfc->stop();
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

        NFC *baton = ObjectWrap::Unwrap<NFC>(info.This());
        baton->context = context;
        baton->pnd = pnd;

        NFCReadWorker* readWorker = new NFCReadWorker(baton, info.This());
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
        SetPrototypeMethod(tpl, "write", NFC::Write);

        Nan::Export(target, "version", Version);
        Nan::Export(target, "scan", Scan);
        Nan::Set(target, Nan::New("NFC").ToLocalChecked(), tpl->GetFunction());
    };
}

NODE_MODULE(nfc, init)
