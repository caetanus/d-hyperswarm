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
    // Handlers registered late must not miss what already happened: the connect
    // path opens the secret-stream (and may receive the peer's first app bytes)
    // before the caller gets the Connection to set onData/onOpen on. So these are
    // properties — decrypted messages that arrive before onData is set are held
    // in earlyMessages and flushed the instant it is, and onOpen fires on the
    // open edge or the moment a handler is set after it, whichever is later, once.
    private void delegate(ubyte[]) nothrow onData_;
    private void delegate() nothrow onOpen_;
    private ubyte[][] earlyMessages;
    private bool openFired;
    /// Delegate invoked when the underlying UDX stream closes.
    void delegate() nothrow onClose;

    /// Decrypted application messages. Setting a handler drains anything that
    /// arrived before it was set, so a peer that writes first is never lost.
    void onData(void delegate(ubyte[]) nothrow cb) nothrow
    {
        onData_ = cb;
        if (cb is null || earlyMessages.length == 0)
            return;
        auto held = earlyMessages;
        earlyMessages = null;
        try
            foreach (m; held)
                cb(m);
        catch (Exception)
        {
        }
    }

    void delegate(ubyte[]) nothrow onData() nothrow
    {
        return onData_;
    }

    /// Fired once when the secret-stream finishes opening. Setting a handler after
    /// the connection is already open fires it immediately (the edge is not lost).
    void onOpen(void delegate() nothrow cb) nothrow
    {
        onOpen_ = cb;
        if (cb !is null && opened && !openFired)
        {
            openFired = true;
            try
                cb();
            catch (Exception)
            {
            }
        }
    }

    void delegate() nothrow onOpen() nothrow
    {
        return onOpen_;
    }

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
            if (ss.opened)
                opened = true;
            if (opened && !openFired && onOpen_ !is null)
            {
                openFired = true;
                onOpen_();
            }
            // Deliver decrypted messages, or hold them until onData is set — a peer
            // that writes before we have a handler must not lose those bytes.
            if (onData_ !is null)
                foreach (m; r.messages)
                    onData_(m);
            else
                foreach (m; r.messages)
                    earlyMessages ~= m.dup;
        }
        catch (Exception)
        {
        }
    }
}

// The connect path opens the secret-stream (and can receive the peer's first app
// bytes) before the caller sets onData — so a peer that writes first must still be
// delivered once a handler registers, and onOpen must not be lost either. Drives
// the real onReadRaw with post-open data frames (no toSend, so the udx stream is
// never touched) after opening both secret-streams in memory.
@("connection buffers app data that arrives before onData is set")
unittest
{
    import hyperswarm.noise.stream : SecretStream;
    import hyperswarm.noise.crypto : ed25519Keypair, Keypair;

    static Keypair kp(ubyte v)
    {
        ubyte[32] s = v;
        return ed25519Keypair(s[]);
    }

    // Open both ends fully (the handshake dance), OUTSIDE any Connection.
    auto a = new SecretStream(true, kp(1)); // the remote peer that writes first
    auto b = new SecretStream(false, kp(2)); // the ss the Connection wraps
    b.start();
    auto forB = a.start();
    ubyte[] forA;
    foreach (_; 0 .. 24)
    {
        if (forB.length)
        {
            auto r = b.feed(forB);
            forB = null;
            forA ~= r.toSend;
        }
        if (forA.length)
        {
            auto r = a.feed(forA);
            forA = null;
            forB ~= r.toSend;
        }
        if (a.opened && b.opened)
            break;
    }
    assert(a.opened && b.opened);

    auto dummyStream = cast(void*) 0xC0FFEE; // unique key; never dereferenced post-open
    ubyte[32] pk;
    auto conn = new Connection(null, dummyStream, b, pk);
    scope (exit)
        g_conns.remove(dummyStream); // don't destroy(): that would touch the udx stream

    // The peer writes before we register onData — the frame must be held, not lost.
    conn.onReadRaw(a.write(cast(const(ubyte)[]) "MANIFEST"));
    assert(conn.opened);

    ubyte[][] got;
    conn.onData = (ubyte[] m) nothrow { got ~= m; }; // setting it drains the buffer
    assert(got.length == 1);
    assert(cast(string) got[0] == "MANIFEST");

    // Once a handler is set, later frames deliver straight through.
    conn.onReadRaw(a.write(cast(const(ubyte)[]) "WANT"));
    assert(got.length == 2);
    assert(cast(string) got[1] == "WANT");

    // onOpen registered after the open edge still fires, exactly once.
    int opens;
    conn.onOpen = () nothrow { opens++; };
    assert(opens == 1);
    conn.onReadRaw(a.write(cast(const(ubyte)[]) "MORE"));
    assert(opens == 1); // not re-fired
}
