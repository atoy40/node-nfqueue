/*
 * Copyright (C) 2014  Anthony Hinsinger
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <node.h>
#include <nan.h>
#include <node_buffer.h>
#include <node_version.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <string.h>

using namespace v8;


class nfqueue : public Nan::ObjectWrap {
  public:
    static void Init(Local<Object> exports);
    Nan::Callback callback;

  private:
    nfqueue() {}
    ~nfqueue() {}

    static Nan::Persistent<Function> constructor;
    static NAN_METHOD(New);
    static NAN_METHOD(Open);
    static NAN_METHOD(Read);
    static NAN_METHOD(Verdict);

    static void PollAsync(uv_poll_t* handle, int status, int events);
    static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data);

    struct nfq_handle *handle;
    struct nfq_q_handle *qhandle;
    struct nlif_handle *nlifh;
    char *buffer_data;
    size_t buffer_length;
};

struct RecvBaton {
  uv_poll_t poll;
  nfqueue *queue;
};

Nan::Persistent<Function> nfqueue::constructor;

void nfqueue::Init(Local<Object> exports) {
  Nan::HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("NFQueue").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "open", Open);
  Nan::SetPrototypeMethod(tpl, "read", Read);
  Nan::SetPrototypeMethod(tpl, "setVerdict", Verdict);

  constructor.Reset(tpl->GetFunction());
  exports->Set(Nan::New("NFQueue").ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(nfqueue::New) {
  Nan::HandleScope scope;
  
  if (info.IsConstructCall()) {
    // Invoked as constructor: `new MyObject(...)`
    nfqueue* nfqueue_instance = new nfqueue();
    nfqueue_instance->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    // Invoked as plain function `MyObject(...)`, turn into construct call.
    Local<Function> cons = Nan::New<Function>(constructor);
    info.GetReturnValue().Set(cons->NewInstance(0, NULL));
  }
}

NAN_METHOD(nfqueue::Open) {
  Nan::HandleScope scope;

  nfqueue* obj = Nan::ObjectWrap::Unwrap<nfqueue>(info.This());

  if (!info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad queue number");
    return;
  }

  obj->handle = nfq_open();
  if (obj->handle == NULL) {
    Nan::ThrowTypeError("Unable to open queue");
    return;
  }

  if (nfq_unbind_pf(obj->handle, AF_INET)) {
    Nan::ThrowTypeError("Unable to unbind queue");
    return;
  }
  nfq_bind_pf(obj->handle, AF_INET);

  obj->qhandle = nfq_create_queue(obj->handle, info[0]->Uint32Value(), &nf_callback, (void*)obj);

  if (obj->qhandle == NULL) {
    Nan::ThrowTypeError("Unable to create queue");
    return;
  }

  if (nfq_set_mode(obj->qhandle, NFQNL_COPY_PACKET, 0xffff) < 0) {
    Nan::ThrowTypeError("Unable to set queue mode");
    return;
  }

  // open and query interface table
  obj->nlifh = nlif_open();
  if (obj->nlifh == NULL) {
    Nan::ThrowTypeError("Unable to open an interface table handle");
    return;
  }
  nlif_query(obj->nlifh);

  return;
}

NAN_METHOD(nfqueue::Read) {
  Nan::HandleScope scope;

  nfqueue* obj = Nan::ObjectWrap::Unwrap<nfqueue>(info.This());

  obj->callback.SetFunction(Local<Function>::Cast(info[0]));

  RecvBaton *baton = new RecvBaton();
  baton->poll.data = baton;
  baton->queue = obj;

  uv_poll_init_socket(uv_default_loop(), &baton->poll, nfq_fd(obj->handle));
  uv_poll_start(&baton->poll, UV_READABLE, PollAsync);

  return;
}

void nfqueue::PollAsync(uv_poll_t* handle, int status, int events) {
  char buf[65535];
  RecvBaton *baton = static_cast<RecvBaton*>(handle->data);
  nfqueue* queue = baton->queue;

  int count = recv(nfq_fd(queue->handle), buf, sizeof(buf), 0);
  nfq_handle_packet(queue->handle, buf, count);
}

int nfqueue::nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
  Nan::HandleScope scope;

  nfqueue* queue = (nfqueue*)data;
  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  int payload_len;
  unsigned char* payload_data;
  char devname[IFNAMSIZ];
  struct timeval tv;

  ph = nfq_get_msg_packet_hdr(nfad);
  payload_len = nfq_get_payload(nfad, &payload_data);

  // get id
  if (ph)
    id = ntohl(ph->packet_id);

  // copy payload into a buffer
  Nan::MaybeLocal<Object> buff = Nan::CopyBuffer((const char*)payload_data, payload_len);

  Local<Object> p = Nan::New<Object>();
  p->Set(Nan::New("len").ToLocalChecked(), Nan::New<Number>(payload_len));
  p->Set(Nan::New("id").ToLocalChecked(), Nan::New<Number>(id));
  p->Set(Nan::New("nfmark").ToLocalChecked(), Nan::New<Number>(nfq_get_nfmark(nfad)));
  if (nfq_get_timestamp(nfad, &tv) == 0)
    p->Set(Nan::New("timestamp").ToLocalChecked(), Nan::New<Number>(tv.tv_sec));
  p->Set(Nan::New("indev").ToLocalChecked(), Nan::New<Number>(nfq_get_indev(nfad)));
  p->Set(Nan::New("physindev").ToLocalChecked(), Nan::New<Number>(nfq_get_physindev(nfad)));
  p->Set(Nan::New("outdev").ToLocalChecked(), Nan::New<Number>(nfq_get_outdev(nfad)));
  p->Set(Nan::New("physoutdev").ToLocalChecked(), Nan::New<Number>(nfq_get_physoutdev(nfad)));
  nfq_get_indev_name(queue->nlifh, nfad, devname);
  p->Set(Nan::New("indev_name").ToLocalChecked(), Nan::New<String>(devname).ToLocalChecked());
  nfq_get_physindev_name(queue->nlifh, nfad, devname);
  p->Set(Nan::New("physindev_name").ToLocalChecked(), Nan::New<String>(devname).ToLocalChecked());
  nfq_get_outdev_name(queue->nlifh, nfad, devname);
  p->Set(Nan::New("outdev_name").ToLocalChecked(), Nan::New<String>(devname).ToLocalChecked());
  nfq_get_physoutdev_name(queue->nlifh, nfad, devname);
  p->Set(Nan::New("physoutdev_name").ToLocalChecked(), Nan::New<String>(devname).ToLocalChecked());

  Local<Value> argv[] = { p, buff.ToLocalChecked() };

  Local<Value> ret = queue->callback.Call(2, argv);

  return ret->Int32Value();
}

NAN_METHOD(nfqueue::Verdict) {
  Nan::HandleScope scope;

  nfqueue* obj = Nan::ObjectWrap::Unwrap<nfqueue>(info.This());
  const unsigned char* buff_data;
  size_t buff_length;

  if (!info[info.Length() - 1]->IsNull()) {
    Local<Object> buff_obj = info[info.Length() - 1]->ToObject();
    buff_data = (unsigned char*)node::Buffer::Data(buff_obj);
    buff_length = node::Buffer::Length(buff_obj);
  } else {
    buff_data = NULL;
    buff_length = 0;
  }

  if (info.Length() == 3) {
    nfq_set_verdict(obj->qhandle, info[0]->Uint32Value(), info[1]->Uint32Value(), buff_length, buff_data);
  } else if (info.Length() == 4) {
    nfq_set_verdict2(obj->qhandle, info[0]->Uint32Value(), info[1]->Uint32Value(), info[2]->Uint32Value(), buff_length, buff_data);
  }

  return;
}

void initAll(Local<Object> exports) {
  nfqueue::Init(exports);
}

NODE_MODULE(nfqueue, initAll)
