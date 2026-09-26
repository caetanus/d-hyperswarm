/// Protomux — many message-oriented protocols (channels) over one framed stream: the
/// Holepunch L6 that sits on a hyperswarm Connection (whose secret-stream keeps message
/// boundaries). A port of protomux 3.11 (github.com/holepunchto/protomux), WIRE-COMPATIBLE
/// with it:
///   message      = uint(sender's channel id) uint(type) payload
///   control (0)  = type 0 batch · 1 open{uint id, string protocol, optionalBuffer id,
///                  handshake…} · 2 reject{uint id} · 3 close{uint id}
///   batch        = 0 0 uint(first id) then per message: buffer(uint(type) payload), where a
///                  0 length switches to uint(next id)
/// Channels pair by (protocol, id): the first remote open with the same key meets the first
/// local channel. The execution model is vibe's: handlers are synchronous delegates (the JS
/// promises they may return are not a thing here — start a task for async work), called
/// from whoever feeds the mux (the connection's data callback).
module hyperswarm.protomux;

import std.conv : to;
import std.exception : enforce;

import hyperswarm.cenc;

/// The byte-level surface of a mux: what writes one frame to the stream, and what tears it
/// down (a protocol violation destroys the whole stream, as in JS).
alias FrameWriter = void delegate(const(ubyte)[] frame) nothrow;
alias Destroyer = void delegate(string why) nothrow;

private enum size_t maxBuffered = 4 * 1024 * 1024;   // messages held for unpaired channels
private enum size_t maxBatch = 8 * 1024 * 1024;

private struct Info
{
    string key;
    string protocol;
    ubyte[] id;
    string[] aliases;
    int pairing;
    int opened;
    uint[] incoming;   // remote ids waiting for a local channel
    uint[] outgoing;   // local ids waiting for the remote open
    int accepting;     // accepted channels (createChannel for a remote open) not yet announced
    Channel lastChannel;
}

private struct Pending
{
    ulong type;
    ubyte[] payload;   // the message after its type (a copy: the frame buffer is reused)
}

private final class Remote
{
    ubyte[] handshake;       // the rest of its open message (the handshake), until paired
    Pending[] pending;       // messages that came before a local channel paired with it
    bool buffering;          // true until a session takes it
    Channel session;
}

/// One message type of a channel. `send` encodes with the codec `C` (a cenc codec struct).
final class Message(C)
{
    private alias T = typeof(C.decode(*(cast(State*) null)));

    private Channel ch;
    private ulong type;
    void delegate(T value, Channel ch) onmessage;

    private this(Channel ch, ulong type, void delegate(T, Channel) onmessage)
    {
        this.ch = ch;
        this.type = type;
        this.onmessage = onmessage;
    }

    /// False when the channel is closed (nothing sent).
    bool send(T value)
    {
        if (ch.closed)
            return false;
        auto mux = ch.mux;
        State s;
        if (mux.corked > 0)
        {
            Uint.preencode(s, type);
            C.preencode(s, value);
            s.buffer = new ubyte[s.end];
            Uint.encode(s, type);
            C.encode(s, value);
            mux.pushBatch(ch.localId, s.buffer);
            return true;
        }
        Uint.preencode(s, ch.localId);
        Uint.preencode(s, type);
        C.preencode(s, value);
        s.buffer = new ubyte[s.end];
        Uint.encode(s, ch.localId);
        Uint.encode(s, type);
        C.encode(s, value);
        mux.write(s.buffer);
        return true;
    }

    private void recv(ref State s)
    {
        auto v = C.decode(s);
        if (onmessage !is null)
            onmessage(v, ch);
    }
}

/// A protocol channel over the mux.
final class Channel
{
    string protocol;
    ubyte[] id;
    string[] aliases;
    Object userData;
    /// The remote's handshake bytes (the rest of its open message), once opened.
    ubyte[] handshake;

    bool opened, closed, destroyed;

    void delegate(Channel ch) onopen;
    void delegate(bool isRemote, Channel ch) onclose;
    void delegate(Channel ch) ondestroy;

    private Protomux mux;
    private Info* info;
    private uint localId, remoteId;
    private void delegate(ref State) [] receivers;   // by message type

    private this(Protomux mux, Info* info, string protocol, ubyte[] id)
    {
        this.mux = mux;
        this.info = info;
        this.protocol = protocol;
        this.id = id;
    }

    /// Add a message type (in order: the n-th added is type n on both sides).
    Message!C addMessage(C)(void delegate(typeof(C.decode(*(cast(State*) null))) value, Channel ch) onmessage = null)
    {
        auto m = new Message!C(this, receivers.length, onmessage);
        receivers ~= (ref State s) { m.recv(s); };
        return m;
    }

    /// Announce the channel to the remote (with the handshake bytes, possibly empty).
    void open(const(ubyte)[] handshakeBytes = null)
    {
        if (closed || localId != 0 || mux.destroying)
            return;   // once, and only while the channel and the mux live
        uint slot;
        if (mux.free.length)
        {
            slot = mux.free[$ - 1];
            mux.free = mux.free[0 .. $ - 1];
        }
        else
        {
            slot = cast(uint) mux.local.length;
            mux.local ~= null;
        }
        // the current entry for THIS channel's key (protocol, id): the Info it was created with
        // may have been collected, or replaced, or be another protocol's that it aliased;
        // pairing must use the queue the remote's opens and rejects consult. (An accepted
        // channel keeps its own: Info.accepting held it.)
        if (remoteId == 0)
            info = mux.get(protocol, id, aliases);
        info.opened++;
        announced = true;
        if (accepting)
        {
            accepting = false;
            info.accepting--;
        }
        info.lastChannel = this;
        localId = slot + 1;
        mux.local[slot] = this;
        if (remoteId == 0)
            info.outgoing ~= localId;

        State s = state(2, 2);
        Uint.preencode(s, localId);
        Utf8.preencode(s, protocol);
        OptionalBuffer.preencode(s, id);
        Raw.preencode(s, handshakeBytes);
        s.buffer = new ubyte[s.end];
        s.buffer[0] = 0;
        s.buffer[1] = 1;
        Uint.encode(s, localId);
        Utf8.encode(s, protocol);
        OptionalBuffer.encode(s, id);
        Raw.encode(s, handshakeBytes);
        mux.write0(s.buffer);
        // (paired with a remote open already: it fully opens through the deferred path — at the
        // end of the frame being handled, or on the next tick — never re-entrantly from here,
        // since an onopen that answers with open() is the normal way to accept)
    }

    /// Close the channel (both sides see onclose).
    void close()
    {
        if (closed)
            return;
        if (localId == 0)
        {
            // never announced: an accepted one is refused (the remote's open would wait
            // forever on a close(0) it ignores); a never-opened local one has nothing to say
            if (remoteId > 0)
            {
                // the refusal first: a throwing onclose/ondestroy must not keep it from the peer
                // (rejectSession drops the remote slot; closeLocal then finds it gone)
                mux.rejectSession(info, remoteId);
                closeLocal(false);
            }
            else
                closeLocal(false);
            return;
        }
        State s = state(2, 2);
        Uint.preencode(s, localId);
        s.buffer = new ubyte[s.end];
        s.buffer[0] = 0;
        s.buffer[1] = 3;
        Uint.encode(s, localId);
        // the close goes out before the id is freed and the callbacks run: an onclose that
        // opens another channel must not reuse this id ahead of the peer learning it closed
        mux.write0(s.buffer);
        closeLocal(false);
    }

    void cork() { mux.cork(); }
    void uncork() { mux.uncork(); }

    // ---- internals -----------------------------------------------------------------------

    private bool opening;
    private bool announced;   // open() counted it in info.opened
    private bool accepting;   // counted in info.accepting

    private void fullyOpen()
    {
        if (opened || closed || opening)
            return;
        opening = true;
        scope (exit)
            opening = false;
        auto r = mux.remote[remoteId - 1];
        handshake = r.handshake;
        r.session = this;
        r.handshake = null;
        if (onopen !is null)
            onopen(this);
        if (mux.destroying || closed)
            return;   // (closed from onopen: closeLocal accounted for what was queued)
        opened = true;
        if (r.buffering)
        {
            r.buffering = false;
            // each leaves the queue (and the accounting) as it is delivered: a handler that
            // closes the channel then accounts only for what is still queued
            while (r.pending.length)
            {
                auto p = r.pending[0];
                r.pending = r.pending[1 .. $];
                mux.buffered -= 512 + p.payload.length;
                State ps = state(0, p.payload.length, p.payload);
                recv(p.type, ps);
                if (mux.destroying || closed)
                    return;
            }
        }
    }

    private void recv(ulong type, ref State s)
    {
        if (type < receivers.length)
            receivers[cast(size_t) type](s);
    }

    private void closeLocal(bool isRemote)
    {
        if (closed)
            return;
        closed = true;
        mux.live.remove(this);
        if (announced)
            info.opened--;
        if (accepting)
        {
            accepting = false;
            info.accepting--;
        }
        if (info.lastChannel is this)
            info.lastChannel = null;
        if (remoteId > 0)
        {
            // messages held for it before it opened: they go, and so does their accounting
            if (auto r = mux.remote[remoteId - 1])
                foreach (ref p; r.pending)
                    mux.buffered -= 512 + p.payload.length;
            mux.remote[remoteId - 1] = null;
            remoteId = 0;
            if (localId > 0)
                mux.free ~= localId - 1;   // the remote acked: the id can be reused
        }
        if (localId > 0)
            mux.local[localId - 1] = null;
        localId = 0;
        mux.gc(info);
        // ondestroy runs even when onclose throws (the throw still reaches the caller)
        scope (exit)
            if (!destroyed)
            {
                destroyed = true;
                if (ondestroy !is null)
                    ondestroy(this);
            }
        if (onclose !is null)
            onclose(isRemote, this);
    }
}

/// The multiplexer over one framed stream (a hyperswarm Connection).
final class Protomux
{
    /// Set before feeding frames; called when the peer breaks the protocol.
    Destroyer destroyer;

    private FrameWriter writer;
    private Remote[] remote;
    private Channel[] local;
    private uint[] free;
    private Info*[string] infos;
    private void delegate(const(ubyte)[] id)[string] notify;
    private size_t buffered;
    private bool destroying;
    private int corked;
    private BatchItem[] batch;   // non-null while corked
    private State batchState;
    private Channel[] deferred;  // channels paired to a remote open, fully opened after the frame
    private bool inFrame;        // inside onFrame: the deferred opens run at its end
    private bool[Channel] live;  // every channel from creation to close (shutdown closes them all)
    private bool flushScheduled;

    private struct BatchItem
    {
        uint localId;
        ubyte[] buffer;
    }

    this(FrameWriter writer)
    {
        this.writer = writer;
    }

    /// Open channels now (the muxer is iterable in JS).
    Channel[] channels()
    {
        Channel[] out_;
        foreach (c; local)
            if (c !is null)
                out_ ~= c;
        return out_;
    }

    bool isIdle() const
    {
        return local.length == free.length;
    }

    /// Create a channel. Null when `unique` and one with this key is already open.
    Channel createChannel(string protocol, const(ubyte)[] id = null, bool unique = true, string[] aliases = null)
    {
        if (destroying)
            return null;
        auto info = get(protocol, id, aliases);
        if (unique && info.opened > 0)
            return null;
        auto ch = new Channel(this, info, protocol, id is null ? null : id.dup);
        ch.aliases = aliases.dup;
        live[ch] = true;
        if (info.incoming.length == 0)
            return ch;
        immutable rid = info.incoming[0];
        info.incoming = info.incoming[1 .. $];
        if (remote[rid - 1] is null)
        {
            live.remove(ch);
            return null;
        }
        ch.remoteId = rid;
        ch.accepting = true;
        info.accepting++;   // keeps the Info (and its key) until it announces or closes
        remote[rid - 1].session = ch;
        deferred ~= ch;   // fully open once the caller has had its chance to set it up
        if (!inFrame)
            scheduleFlush();   // (JS: queueTick) — the caller's code runs first
        return ch;
    }

    /// Called for every remote open of (protocol, id) with no local channel waiting — create
    /// (and open) one in it to accept; return without creating to refuse.
    void pair(string protocol, const(ubyte)[] id, void delegate(const(ubyte)[] id) cb)
    {
        notify[toKey(protocol, id)] = cb;
    }

    void unpair(string protocol, const(ubyte)[] id)
    {
        notify.remove(toKey(protocol, id));
    }

    bool isOpened(string protocol, const(ubyte)[] id = null)
    {
        if (auto p = toKey(protocol, id) in infos)
            return (*p).opened > 0;
        return false;
    }

    void cork()
    {
        if (++corked == 1)
        {
            batch = [];
            batchState = state(0, 1);
        }
    }

    void uncork()
    {
        if (--corked == 0)
        {
            sendBatch();
            batch = null;
        }
    }

    /// Feed one frame (one secret-stream message) from the stream.
    void onFrame(const(ubyte)[] frame)
    {
        if (frame.length == 0 || destroying)
            return;
        inFrame = true;
        scope (exit)
            inFrame = false;
        try
        {
            // decode views into the frame; messages held for later are copied
            auto buf = cast(ubyte[]) frame;
            State s = state(0, buf.length, buf);
            decode(Uint.decode(s), s);
            flushDeferred();
        }
        catch (Exception e)
            safeDestroy(e.msg);
    }

    /// The stream closed: every channel closes as if the remote closed it.
    void shutdown()
    {
        destroying = true;
        deferred = null;
        // every live channel — opened, accepted and waiting, created and never opened
        Exception first;
        foreach (c; live.keys)
            if (!c.closed)
            {
                try
                    c.closeLocal(true);
                catch (Exception e)   // one handler's throw must not keep the rest open
                    if (first is null)
                        first = e;
            }
        live = null;
        if (first !is null)
            throw first;
    }

    // ---- internals -----------------------------------------------------------------------

    private void scheduleFlush()
    {
        import vibe.core.core : runTask;

        if (flushScheduled)
            return;
        flushScheduled = true;
        runTask(() nothrow {
            import vibe.core.core : yield;

            // runTask starts the task at once; yield first, so the code that created the
            // channel runs to its end (sets handlers, opens) before it fully opens — queueTick
            try
                yield();
            catch (Exception)
            {
            }
            flushScheduled = false;
            try
                flushDeferred();
            catch (Exception e)
                safeDestroy(e.msg);
        });
    }

    private void flushDeferred()
    {
        if (destroying)
        {
            deferred = null;
            return;
        }
        while (deferred.length)
        {
            auto d = deferred;
            deferred = null;
            foreach (i, ch; d)
            {
                if (destroying)
                {
                    // shut down from an onopen: the rest close instead of opening
                    foreach (rest; d[i .. $])
                        if (!rest.closed)
                            rest.closeLocal(true);
                    return;
                }
                ch.fullyOpen();
                // (it may itself have shut the mux down from its onopen: it closes too)
                if (destroying && !ch.closed)
                    ch.closeLocal(true);
            }
        }
    }

    private void write(const(ubyte)[] buf)
    {
        writer(buf);
    }

    private void write0(ubyte[] buf)
    {
        if (corked > 0)
        {
            pushBatch(0, buf[1 .. $]);
            return;
        }
        writer(buf);
    }

    private void pushBatch(uint localId, ubyte[] buf)
    {
        if (batchState.end >= maxBatch)
        {
            sendBatch();
            batch = [];
            batchState = state(0, 1);
        }
        if (batch.length == 0 || batch[$ - 1].localId != localId)
        {
            batchState.end++;
            Uint.preencode(batchState, localId);
        }
        Buffer.preencode(batchState, buf);
        batch ~= BatchItem(localId, buf);
    }

    private void sendBatch()
    {
        if (batch.length == 0)
            return;
        auto s = batchState;
        s.buffer = new ubyte[s.end];
        s.buffer[s.start++] = 0;
        s.buffer[s.start++] = 0;
        uint prev = batch[0].localId;
        Uint.encode(s, prev);
        foreach (ref b; batch)
        {
            if (prev != b.localId)
            {
                s.buffer[s.start++] = 0;
                Uint.encode(s, prev = b.localId);
            }
            Buffer.encode(s, b.buffer);
        }
        writer(s.buffer);
    }

    private Info* get(string protocol, const(ubyte)[] id, string[] aliases = null)
    {
        immutable key = toKey(protocol, id);
        if (auto p = key in infos)
            return *p;
        auto info = new Info(key, protocol, id is null ? null : id.dup);
        infos[key] = info;
        foreach (a; aliases)
        {
            immutable ak = toKey(a, id);
            if (ak in infos)
                continue;   // an alias never hides a protocol that is already there
            info.aliases ~= ak;
            infos[ak] = info;
        }
        return info;
    }

    private void gc(Info* info)
    {
        if (info.opened == 0 && info.outgoing.length == 0 && info.incoming.length == 0 && info.accepting == 0)
        {
            // only this entry: a stale Info must not remove the one that replaced it
            if (auto cur = info.key in infos)
                if (*cur is info)
                    infos.remove(info.key);
            foreach (a; info.aliases)
                if (auto cur = a in infos)
                    if (*cur is info)
                        infos.remove(a);
        }
    }

    private void decode(ulong remoteId, ref State s)
    {
        if (destroying)
            return;
        immutable type = Uint.decode(s);
        if (remoteId == 0)
        {
            onControl(type, s);
            return;
        }
        auto r = remoteId <= remote.length ? remote[cast(size_t)(remoteId - 1)] : null;
        if (r is null)
            return;   // a closed channel: could be a message in flight
        // accepted earlier in this frame (its pair callback has returned): open it now, so its
        // messages flow instead of piling up until the frame ends
        if (r.buffering && r.session !is null && deferred.length)
        {
            flushDeferred();
            // (its onopen may have closed it or shut the mux down: look again)
            if (destroying)
                return;
            r = remoteId <= remote.length ? remote[cast(size_t)(remoteId - 1)] : null;
            if (r is null)
                return;
        }
        if (r.buffering)
        {
            auto payload = s.buffer[s.start .. s.end].dup;
            r.pending ~= Pending(type, payload);
            buffered += 512 + payload.length;
            enforce(buffered <= maxBuffered, "protomux: too much buffered for unpaired channels");
            return;
        }
        if (r.session !is null)
            r.session.recv(type, s);
    }

    private void onControl(ulong type, ref State s)
    {
        switch (type)
        {
        case 0: onBatch(s); break;
        case 1: onOpen(s); break;
        case 2: onReject(s); break;
        case 3: onClose(s); break;
        default: break;
        }
    }

    private bool inBatch;

    private void onBatch(ref State s)
    {
        // a batch inside a batch: nobody sends that, and nesting them would recurse without
        // bound (a peer could exhaust the stack — an Error, not a catchable Exception, in D)
        enforce(!inBatch, "protomux: nested batch");
        inBatch = true;
        scope (exit)
            inBatch = false;
        immutable end = s.end;
        ulong remoteId = Uint.decode(s);
        while (s.end > s.start && !destroying)   // (a callback may shut the mux down mid-batch)
        {
            immutable len = cast(size_t) Uint.decode(s);
            if (len == 0)
            {
                remoteId = Uint.decode(s);
                continue;
            }
            enforce(s.start + len <= end, "protomux: batch entry out of bounds");
            s.end = s.start + len;
            decode(remoteId, s);
            s.start = s.end;
            s.end = end;
        }
    }

    private void onOpen(ref State s)
    {
        immutable remoteIdL = Uint.decode(s);
        immutable protocol = Utf8.decode(s);
        auto id = OptionalBuffer.decode(s);
        if (remoteIdL == 0)
        {
            rejectSession(null, 0);   // the control session is not openable
            return;
        }
        // the remote may grow its ids by one at most (checked before narrowing)
        enforce(remoteIdL <= remote.length + 1, "protomux: invalid open message");
        immutable remoteId = cast(uint) remoteIdL;
        immutable rid = remoteId - 1;
        auto info = get(protocol, id);
        if (remote.length == rid)
            remote ~= null;   // the remote may grow its ids by one
        enforce(rid < remote.length && remote[rid] is null, "protomux: invalid open message");
        auto hs = s.buffer[s.start .. s.end].dup;   // the handshake: the rest of the open

        if (info.outgoing.length > 0)
        {
            immutable localId = info.outgoing[0];
            info.outgoing = info.outgoing[1 .. $];
            auto session = local[localId - 1];
            if (session is null)
            {
                free ~= localId - 1;   // we closed it already: ignore
                gc(info);
                return;
            }
            auto r = new Remote;
            r.handshake = hs;
            remote[rid] = r;
            session.remoteId = remoteId;
            session.fullyOpen();
            return;
        }

        auto r = new Remote;
        r.handshake = hs;
        r.buffering = true;
        remote[rid] = r;
        info.pairing++;
        info.incoming ~= remoteId;
        requestSession(protocol, id, info);
    }

    private void requestSession(string protocol, const(ubyte)[] id, Info* info)
    {
        auto cb = toKey(protocol, id) in notify;
        if (cb is null)
            cb = toKey(protocol, null) in notify;
        if (cb !is null)
            (*cb)(id);
        if (--info.pairing > 0)
            return;
        while (info.incoming.length)
        {
            immutable rid = info.incoming[0];
            info.incoming = info.incoming[1 .. $];
            rejectSession(info, rid);
        }
        gc(info);
    }

    private void rejectSession(Info* info, uint remoteId)
    {
        if (remoteId > 0)
        {
            auto r = remote[remoteId - 1];
            if (r !is null)
                foreach (ref p; r.pending)
                    buffered -= 512 + p.payload.length;
            remote[remoteId - 1] = null;
        }
        State s = state(2, 2);
        Uint.preencode(s, remoteId);
        s.buffer = new ubyte[s.end];
        s.buffer[0] = 0;
        s.buffer[1] = 2;
        Uint.encode(s, remoteId);
        write0(s.buffer);
    }

    private void onReject(ref State s)
    {
        immutable localIdL = Uint.decode(s);
        enforce(localIdL > 0 && localIdL <= local.length, "protomux: invalid reject message");
        immutable localId = cast(uint) localIdL;
        foreach (key, info; infos)
        {
            foreach (i, o; info.outgoing)
                if (o == localId)
                {
                    info.outgoing = info.outgoing[0 .. i] ~ info.outgoing[i + 1 .. $];
                    auto session = local[localId - 1];
                    free ~= localId - 1;
                    if (session !is null)
                        session.closeLocal(true);
                    gc(info);
                    return;
                }
        }
        throw new Exception("protomux: invalid reject message");
    }

    private void onClose(ref State s)
    {
        immutable remoteId = Uint.decode(s);
        if (remoteId == 0 || remoteId > remote.length)
            return;   // (JS ignores a close of a channel it does not have)
        auto r = remote[cast(size_t)(remoteId - 1)];
        if (r is null)
            return;
        if (r.session !is null)
            r.session.closeLocal(true);
    }

    private void safeDestroy(string why) nothrow
    {
        destroying = true;
        if (destroyer !is null)
            destroyer(why);
    }
}

private string toKey(string protocol, const(ubyte)[] id)
{
    import std.digest : toHexString, LetterCase;

    return protocol ~ "##" ~ (id.length ? toHexString!(LetterCase.lower)(id) : "");
}

// ---- tests: two muxes wired back to back ------------------------------------------------

unittest
{
    // frames queued between the two sides, delivered by pump() (like a stream would)
    ubyte[][] toB, toA;
    Protomux a, b;
    a = new Protomux((const(ubyte)[] f) nothrow { toB ~= f.dup; });
    b = new Protomux((const(ubyte)[] f) nothrow { toA ~= f.dup; });
    void pump()
    {
        while (toB.length || toA.length)
        {
            auto x = toB; toB = null;
            foreach (f; x) b.onFrame(f);
            auto y = toA; toA = null;
            foreach (f; y) a.onFrame(f);
        }
    }

    string[] got;
    bool aOpen, bOpen;

    // B accepts channels of "echo" as they come
    b.pair("echo", null, (const(ubyte)[] id) {
        auto ch = b.createChannel("echo");
        Message!Utf8 reply;
        ch.onopen = (Channel c) { bOpen = true; };
        auto m = ch.addMessage!Utf8((string v, Channel c) { reply.send("echo:" ~ v); });
        reply = m;
        ch.open(cast(const(ubyte)[]) "hi-from-b");
    });

    auto ca = a.createChannel("echo");
    ca.onopen = (Channel c) { aOpen = true; assert(cast(string) c.handshake == "hi-from-b"); };
    auto ma = ca.addMessage!Utf8((string v, Channel c) { got ~= v; });
    ca.open();
    ma.send("one");   // sent before the remote paired: B buffers it until it does
    pump();
    ma.send("two");
    pump();
    assert(aOpen && bOpen);
    assert(got == ["echo:one", "echo:two"], got.to!string);

    // batching: corked sends go out as one frame
    ca.cork();
    ma.send("three");
    ma.send("four");
    assert(toB.length == 0);
    ca.uncork();
    assert(toB.length == 1);
    pump();
    assert(got == ["echo:one", "echo:two", "echo:three", "echo:four"], got.to!string);

    // close: both sides see it
    bool closedA;
    ca.onclose = (bool isRemote, Channel c) { closedA = true; };
    ca.close();
    pump();
    assert(closedA && ca.closed);

    // a protocol nobody pairs is rejected: the opener sees onclose(remote)
    bool rejected;
    auto cx = a.createChannel("nobody-home");
    cx.onclose = (bool isRemote, Channel c) { rejected = isRemote; };
    cx.open();
    pump();
    assert(rejected);
}

unittest
{
    // an accepted channel whose onopen answers with open() (no recursion), and a wire id past
    // 32 bits addressing nothing (ignored, not aliased onto channel 1)
    ubyte[][] toB, toA;
    auto a = new Protomux((const(ubyte)[] f) nothrow { toB ~= f.dup; });
    auto b = new Protomux((const(ubyte)[] f) nothrow { toA ~= f.dup; });
    void pump()
    {
        while (toB.length || toA.length)
        {
            auto x = toB; toB = null;
            foreach (f; x) b.onFrame(f);
            auto y = toA; toA = null;
            foreach (f; y) a.onFrame(f);
        }
    }
    int opens;
    Channel bc;
    b.pair("x", null, (const(ubyte)[] id) {
        bc = b.createChannel("x");
        bc.onopen = (Channel c) { opens++; c.open(); };
    });
    auto ac = a.createChannel("x");
    bool aOpened;
    ac.onopen = (Channel c) { aOpened = true; };
    ac.open();
    pump();
    assert(opens == 1 && aOpened && bc.opened && !bc.closed);

    State s;
    Uint.preencode(s, 1UL << 32); s.end += 2;
    s.buffer = new ubyte[s.end];
    Uint.encode(s, 1UL << 32); s.buffer[s.start++] = 3; s.buffer[s.start++] = 1;
    b.onFrame(s.buffer);
    assert(!bc.closed);
}

unittest
{
    // a nested batch is refused (destroyer called), never recursed into
    string why;
    auto m = new Protomux((const(ubyte)[] f) nothrow {});
    m.destroyer = (string w) nothrow { why = w; };
    ubyte[] frame = [0, 0, 1];   // batch, first id 1
    foreach (_; 0 .. 3)
        frame ~= [cast(ubyte) 4, 0, 0, 0, 0];   // entries that are themselves batches…
    m.onFrame(frame);
    // (the inner "batch" entries decode as control id 0 type 0 only if addressed to 0; build one that is)
    ubyte[] nested = [0, 0, 0, 3, 0, 0, 0];      // batch to id 0, entry len 3 = [0 0 0] = another batch
    auto m2 = new Protomux((const(ubyte)[] f) nothrow {});
    string why2;
    m2.destroyer = (string w) nothrow { why2 = w; };
    m2.onFrame(nested);
    assert(why2.length > 0, "nested batch not refused");
}
