/// An encrypted connection over a UDX stream: the transport a hyperdht connect
/// yields. A UDX stream carries a secret-stream built from the peer-handshake
/// keys (SecretStream.fromHandshake); this wraps the two so callers see a plain
/// send/receive of decrypted application bytes.
///
/// The udx read callback is a C-ABI function that only gets the stream pointer,
/// so we keep a process-wide registry from stream pointer to Connection. This is
/// safe without locking: the facade loop and every callback run on one vibe
/// thread cooperatively (a C callback never yields), so the map is only touched
/// between yield points.
module hyperswarm.connection;

import hyperswarm.udx.udx;
import hyperswarm.udx.facade : uv_buf_t;
import hyperswarm.noise.stream : SecretStream;

private __gshared Connection[void*] g_conns;

/// The udx read callback: route decrypted-stream input to the owning Connection.
extern (C) void hsConnRead(void* stream, ptrdiff_t len, const(uv_buf_t)* buf) nothrow
{
    if (len <= 0)
        return;
    if (auto c = stream in g_conns)
        c.onReadRaw(cast(ubyte[]) buf.base[0 .. len]);
}

extern (C) void hsConnClose(void* stream, int status) nothrow
{
    g_conns.remove(stream);
}

extern (C) void hsConnFinalize(void* stream) nothrow {}

final class Connection
{
    private void* udx; // udx instance (for write sizing)
    private void* stream; // opaque udx_stream block pointer
    private SecretStream ss;
    ubyte[32] remotePublicKey;
    private ubyte[][] keep; // write bufs/reqs kept alive until acked
    bool opened;
    /// Delegate invoked with each decrypted application message.
    void delegate(ubyte[]) nothrow onData;

    this(void* udx, void* stream, SecretStream ss, ubyte[32] remotePublicKey) nothrow
    {
        this.udx = udx;
        this.stream = stream;
        this.ss = ss;
        this.remotePublicKey = remotePublicKey;
        g_conns[stream] = this;
    }

    /// Frame + send raw secret-stream bytes over the UDX stream.
    private void writeRaw(ubyte[] data) nothrow
    {
        if (data.length == 0)
            return;
        try
        {
            auto req = new ubyte[](hs_udx_stream_write_sizeof(1));
            auto d = data.dup;
            keep ~= req;
            keep ~= d;
            auto b = uv_buf_t(cast(char*) d.ptr, d.length);
            hs_udx_stream_write(req.ptr, stream, &b, 1, null);
        }
        catch (Exception)
        {
        }
    }

    /// Emit the secret-stream setup frame (call once after connecting).
    void start() nothrow
    {
        try
            writeRaw(ss.start());
        catch (Exception)
        {
        }
    }

    /// Send encrypted application data to the peer.
    void write(scope const(ubyte)[] data) nothrow
    {
        try
            writeRaw(ss.write(data));
        catch (Exception)
        {
        }
    }

    // Called from the C read callback with raw stream bytes.
    package void onReadRaw(ubyte[] raw) nothrow
    {
        try
        {
            auto r = ss.feed(raw);
            if (r.toSend.length)
                writeRaw(r.toSend);
            if (ss.opened)
                opened = true;
            if (onData !is null)
                foreach (m; r.messages)
                    onData(m);
        }
        catch (Exception)
        {
        }
    }
}
