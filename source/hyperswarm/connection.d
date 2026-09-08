/// An encrypted connection over a UDX stream: the transport a hyperdht connect
/// yields. A UDX stream carries a secret-stream built from the peer-handshake
/// keys (SecretStream.fromHandshake); this wraps the two so callers see a plain
/// send/receive of decrypted application bytes.
///
/// The udx read/ack callbacks are C-ABI functions that only get a pointer, so we
/// keep process-wide registries from stream/request pointer to the owning
/// Connection. This is safe without locking as long as a given udx socket is driven
/// by a single vibe thread (a C callback never yields); the maps are keyed by
/// distinct heap pointers, so independent instances don't collide.
module hyperswarm.connection;

import hyperswarm.udx.udx;
import hyperswarm.udx.facade : uv_buf_t;
import hyperswarm.noise.stream : SecretStream;

private __gshared Connection[void*] g_conns; // stream ptr -> Connection
private __gshared Connection[void*] g_writeOwner; // write-req ptr -> Connection

/// The udx read callback: route decrypted-stream input to the owning Connection.
extern (C) void hsConnRead(void* stream, ptrdiff_t len, const(uv_buf_t)* buf) nothrow
{
    if (len <= 0)
        return;
    if (auto c = stream in g_conns)
        c.onReadRaw(cast(ubyte[]) buf.base[0 .. len]);
}

/// The udx write-ack callback: the datagram is sent, so release its held buffers.
extern (C) void hsConnAck(void* req, int status, int unordered) nothrow
{
    if (auto c = req in g_writeOwner)
    {
        c.pending.remove(req);
        g_writeOwner.remove(req);
    }
}

extern (C) void hsConnClose(void* stream, int status) nothrow
{
    if (auto c = stream in g_conns)
    {
        auto conn = *c;
        conn.closed = true;
        g_conns.remove(stream);
        // release any still-inflight write buffers for this connection
        foreach (req; conn.pending.keys)
            g_writeOwner.remove(req);
        conn.pending = null;
        if (conn.onClose !is null)
            conn.onClose();
    }
}

extern (C) void hsConnFinalize(void* stream) nothrow {}

final class Connection
{
    private void* udx; // udx instance (for write sizing)
    private void* stream; // opaque udx_stream block pointer
    private SecretStream ss;
    ubyte[32] remotePublicKey;
    // In-flight writes: request-block ptr -> [request block, payload], kept alive
    // until udx acks (hsConnAck), so a long-lived connection doesn't accumulate
    // every byte it ever sent.
    private ubyte[][][void*] pending;
    bool opened;
    bool closed;
    /// Delegate invoked with each decrypted application message.
    void delegate(ubyte[]) nothrow onData;
    /// Delegate invoked once, when the secret-stream finishes opening.
    void delegate() nothrow onOpen;
    /// Delegate invoked when the underlying UDX stream closes.
    void delegate() nothrow onClose;

    this(void* udx, void* stream, SecretStream ss, ubyte[32] remotePublicKey) nothrow
    {
        this.udx = udx;
        this.stream = stream;
        this.ss = ss;
        this.remotePublicKey = remotePublicKey;
        g_conns[stream] = this;
    }

    /// Tear the connection down (destroys the UDX stream; the close callback then
    /// clears the registries and fires onClose).
    void destroy() nothrow
    {
        if (closed)
            return;
        closed = true;
        try
            hs_udx_stream_destroy(stream);
        catch (Exception)
        {
        }
    }

    /// Frame + send raw secret-stream bytes over the UDX stream.
    private void writeRaw(ubyte[] data) nothrow
    {
        if (closed || data.length == 0)
            return;
        try
        {
            auto req = new ubyte[](hs_udx_stream_write_sizeof(1));
            auto d = data.dup;
            pending[req.ptr] = [req, d];
            g_writeOwner[req.ptr] = this;
            auto b = uv_buf_t(cast(char*) d.ptr, d.length);
            hs_udx_stream_write(req.ptr, stream, &b, 1, &hsConnAck);
        }
        catch (Exception)
        {
        }
    }

    /// Emit the secret-stream setup frame (call once after connecting).
    void start() nothrow
    {
        if (closed)
            return;
        try
            writeRaw(ss.start());
        catch (Exception)
        {
        }
    }

    /// Send encrypted application data to the peer.
    void write(scope const(ubyte)[] data) nothrow
    {
        if (closed)
            return;
        try
            writeRaw(ss.write(data));
        catch (Exception)
        {
        }
    }

    // Called from the C read callback with raw stream bytes.
    package void onReadRaw(ubyte[] raw) nothrow
    {
        if (closed)
            return;
        try
        {
            auto r = ss.feed(raw);
            if (r.toSend.length)
                writeRaw(r.toSend);
            immutable wasOpen = opened;
            if (ss.opened)
                opened = true;
            if (opened && !wasOpen && onOpen !is null)
                onOpen();
            if (onData !is null)
                foreach (m; r.messages)
                    onData(m);
        }
        catch (Exception)
        {
        }
    }
}
