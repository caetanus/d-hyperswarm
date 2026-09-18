/// D binding to the vendored libudx, via the controlled `hs_udx_*` C-ABI surface
/// the amalgamation exposes (vendor/libudx-amalgam/udx_amalgam.cpp). The udx
/// structs are opaque here: callers allocate a byte block of the size the
/// hs_udx_sizeof_* helpers report and pass its pointer. Callbacks are extern(C)
/// functions whose ABI matches the udx:: callback types the wrappers cast to.
///
/// The loop these run on is a hyperswarm.udx.facade.Loop; pass `loop.chandle` as
/// the `loop` argument to hs_udx_init.
module hyperswarm.udx.udx;

import hyperswarm.udx.facade : uv_buf_t;

// The forwarders are C++ over C libudx — no exception can cross them, so the
// binding is nothrow (lets nothrow callbacks call these).
extern (C):
nothrow:

// Sizes for allocating the opaque udx structs.
size_t hs_udx_sizeof_udx();
size_t hs_udx_sizeof_socket();
size_t hs_udx_sizeof_stream();

// udx instance.
int hs_udx_init(void* loop, void* udx, void* on_idle);

// Sockets.
int hs_udx_socket_init(void* u, void* s, void* close_cb);
int hs_udx_socket_bind(void* s, const(void)* addr, uint flags);
int hs_udx_socket_getsockname(void* s, void* name, int* name_len);
int hs_udx_socket_close(void* s);

// Socket datagrams (non-stream): dht-rpc rides on these, sharing the socket with
// udx streams. recv_start's callback fires for packets that aren't udx-stream
// packets; send transmits one datagram.
size_t hs_udx_sizeof_socket_send();
int hs_udx_socket_send(void* req, void* s, const(uv_buf_t)* bufs, uint bufs_len, const(void)* addr, void* cb);
int hs_udx_socket_send_ttl(void* req, void* s, const(uv_buf_t)* bufs, uint bufs_len, const(void)* addr, int ttl, void* cb);
int hs_udx_socket_recv_start(void* s, void* recv_cb);

// Streams.
int hs_udx_stream_init(void* u, void* stream, uint local_id, void* close_cb, void* finalize_cb);
int hs_udx_stream_connect(void* stream, void* socket, uint remote_id, const(void)* remote_addr);
int hs_udx_stream_change_remote(void* stream, void* socket, uint remote_id, const(void)* remote_addr, void* remote_changed_cb);
int hs_udx_stream_firewall(void* stream, void* firewall_cb);
int hs_udx_stream_read_start(void* stream, void* read_cb);
int hs_udx_stream_write_sizeof(int nwbufs);
int hs_udx_stream_write(void* req, void* stream, const(uv_buf_t)* bufs, uint bufs_len, void* ack_cb);
int hs_udx_stream_destroy(void* stream);

// Callback ABIs (extern(C) functions passed as void* to the wrappers above).
alias UdxIdleCb = extern (C) void function(void* udx) nothrow;
alias UdxSocketCloseCb = extern (C) void function(void* socket) nothrow;
alias UdxStreamCloseCb = extern (C) void function(void* stream, int status) nothrow;
alias UdxStreamFinalizeCb = extern (C) void function(void* stream) nothrow;
alias UdxStreamRemoteChangedCb = extern (C) void function(void* stream) nothrow;
alias UdxStreamReadCb = extern (C) void function(void* stream, ptrdiff_t read_len, const(uv_buf_t)* buf) nothrow;
alias UdxStreamFirewallCb = extern (C) int function(void* stream, void* socket, const(void)* from) nothrow;
alias UdxStreamAckCb = extern (C) void function(void* req, int status, int unordered) nothrow;
alias UdxSocketRecvCb = extern (C) void function(void* socket, ptrdiff_t read_len,
    const(uv_buf_t)* buf, const(void)* from) nothrow;
alias UdxSocketSendCb = extern (C) void function(void* req, int status) nothrow;
