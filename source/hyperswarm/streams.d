/// Byte streams over protomux channels, and a TCP bridge on top of them — the L7 carrier:
/// real HTTP (or any TCP protocol) between two peers, many connections at once over ONE
/// hyperswarm connection.
///
/// A ChannelStream is one channel of protocol `streamProtocol`, a fresh random id per
/// stream (so any number of them pair independently), the opener's handshake naming the
/// service it wants. Three messages, in this order on both sides:
///   0 data   raw bytes (at most what the receiver has granted)
///   1 credit uint: more bytes the receiver lets the sender send
///   2 end    uint (0): the sender will send no more (TCP's FIN — a half-close)
/// Flow control is per stream: each side may send `streamWindow` bytes before its first
/// credit, and a reader grants back what it has consumed once that reaches half the
/// window — so a big download on one stream never buries the others (or the
/// application's own channels) in the shared connection.
///
/// The bridge: `forwardTcp` listens on a local port and carries each accepted TCP
/// connection to the peer as a stream for `service`; `serveTcp` answers such streams by
/// connecting to the local address registered for the service. A browser pointed at the
/// forwarded port speaks plain HTTP to the peer's server — nothing in between parses it.
module hyperswarm.streams;

import hyperswarm.protomux;
import hyperswarm.cenc;

import core.time : Duration, seconds, msecs, MonoTime;
import std.algorithm.comparison : min;
import vibe.core.core : runTask, sleep;
import vibe.core.task : Task;
import vibe.core.sync : LocalManualEvent, createManualEvent;

/// The protomux protocol name of a stream channel.
enum streamProtocol = "hyperswarm/stream/1";
/// Bytes a side may send before the receiver's first credit: the initial window both
/// sides assume. A receiver may widen its own window past it (see `window` on open/accept)
/// by granting the difference as credit as soon as the channel opens — credit is additive,
/// so the wire needs no negotiation.
enum size_t streamWindow = 1024 * 1024;
/// Largest data message (one secret-stream message each).
enum size_t streamChunk = 64 * 1024;
/// How long a closed stream's last bytes may take to leave through a stalled socket.
enum Duration drainTimeout = 10.seconds;

/// One bidirectional byte stream over a protomux channel. Blocking calls (`read`,
/// `write`, `open`) must run in a vibe task; the handlers run from whoever feeds the mux.
final class ChannelStream
{
    private Channel ch;
    private Message!Raw data;
    private Message!Uint credit;
    private Message!Uint fin;
    private LocalManualEvent ev;

    private ulong sendCredit = streamWindow;   // what the remote still lets us send
    private ulong recvAllowed = streamWindow;  // what we granted and did not receive yet
    private size_t recvWindow = streamWindow;  // this side's receive window (grown by grow())
    private ubyte[][] inq;                     // received, not read yet
    private size_t inqOff;                     // read so far of inq[0]
    private size_t consumed;                   // read and not granted back yet
    private bool opened_, remoteEnded, localEnded, closed_;

    /// The service the opener asked for (its handshake) — set on the accepting side.
    string service;
    /// Called once when the stream closes (either side): whoever blocks on something
    /// else for this stream (a socket) is woken here.
    void delegate() nothrow onClosed;

    private this(Channel ch)
    {
        this.ch = ch;
        ev = createManualEvent();
        data = ch.addMessage!Raw((ubyte[] b, Channel c) { onData(b); });
        credit = ch.addMessage!Uint((ulong n, Channel c) {
            sendCredit += n;
            ev.emit();
        });
        fin = ch.addMessage!Uint((ulong _, Channel c) {
            remoteEnded = true;
            ev.emit();
        });
        ch.onopen = (Channel c) {
            opened_ = true;
            ev.emit();
        };
        ch.onclose = (bool isRemote, Channel c) { markClosed(); };
    }

    private void markClosed() nothrow
    {
        if (closed_)
            return;
        closed_ = true;
        ev.emit();
        if (onClosed !is null)
            onClosed();
    }

    private void onData(ubyte[] b)
    {
        if (remoteEnded || b.length > recvAllowed)
        {
            // more than granted (or data after its end): the remote broke the protocol
            ch.close();
            return;
        }
        recvAllowed -= b.length;
        if (b.length)
            inq ~= b.dup;   // the slice is the mux's frame buffer
        ev.emit();
    }

    // Widen this side's receive window to `window` (never narrows): the extra is granted
    // at once. Called once the channel is open.
    private void grow(size_t window)
    {
        if (window <= recvWindow || closed_)
            return;
        immutable extra = window - recvWindow;
        recvWindow = window;
        recvAllowed += extra;
        credit.send(extra);
    }

    /// Open a stream to `service` on the remote end of `mux`. Throws if the remote rejects
    /// the channel (nobody accepts streams there) or `timeout` passes; a service the remote
    /// does not offer opens and is closed at once (the first read returns 0).
    static ChannelStream open(Protomux mux, string service, Duration timeout = 10.seconds,
        size_t window = streamWindow)
    {
        import std.random : uniform;

        ubyte[16] id;
        foreach (ref b; id)
            b = cast(ubyte) uniform(0, 256);
        auto ch = mux.createChannel(streamProtocol, id[], false);
        if (ch is null)
            throw new Exception("stream: cannot create a channel");
        auto s = new ChannelStream(ch);
        ch.open(cast(const(ubyte)[]) service);
        immutable deadline = MonoTime.currTime + timeout;
        auto c = s.ev.emitCount;
        while (!s.opened_ && !s.closed_)
        {
            immutable left = deadline - MonoTime.currTime;
            if (left <= Duration.zero)
            {
                ch.close();
                throw new Exception("stream: " ~ service ~ " did not open in time");
            }
            c = s.ev.wait(left, c);
        }
        if (!s.opened_)
            throw new Exception("stream: " ~ service ~ " refused");
        s.grow(window);
        return s;
    }

    /// Accept the remote's streams on `mux`: `onStream` runs in its own task per stream
    /// (its `service` says what the opener wants; close it to refuse) and owns it: the stream
    /// is closed when `onStream` returns. At most
    /// `maxStreams` at once: past that the remote's opens are rejected (each stream can
    /// hold a window of data, a task and a socket — a peer must not open them unbounded).
    static void accept(Protomux mux, void delegate(ChannelStream s) onStream, size_t maxStreams = 32,
        size_t window = streamWindow)
    {
        auto live = new size_t;
        mux.pair(streamProtocol, null, (const(ubyte)[] id) {
            if (*live >= maxStreams)
                return;   // no channel created: protomux rejects the open
            auto ch = mux.createChannel(streamProtocol, id, false);
            if (ch is null)
                return;
            auto s = new ChannelStream(ch);
            ++*live;
            // the slot is held until the handler is done (its socket, its connect attempt),
            // or until the channel closes if the handler never started
            auto started = new bool;
            ch.onclose = (bool isRemote, Channel c) {
                if (!*started)
                    --*live;
                s.markClosed();
            };
            ch.onopen = (Channel c) {
                s.opened_ = true;
                s.service = cast(string) c.handshake.idup;
                s.grow(window);
                s.ev.emit();
                *started = true;
                runTask((ChannelStream st) nothrow {
                    try
                        onStream(st);
                    catch (Exception)
                    {
                    }
                    st.close();
                    --*live;
                }, s);
            };
            ch.open();
        });
    }

    bool isOpen() const nothrow { return opened_ && !closed_; }

    /// Up to buf.length bytes; blocks until some arrive. 0 = the remote ended (or closed).
    size_t read(ubyte[] buf)
    {
        auto c = ev.emitCount;
        while (inq.length == 0 && !remoteEnded && !closed_)
            c = ev.wait(c);
        size_t n;
        while (n < buf.length && inq.length)
        {
            auto head = inq[0][inqOff .. $];
            immutable k = min(head.length, buf.length - n);
            buf[n .. n + k] = head[0 .. k];
            n += k;
            inqOff += k;
            if (inqOff == inq[0].length)
            {
                inq = inq[1 .. $];
                inqOff = 0;
            }
        }
        consumed += n;
        // grant back often (an eighth of the window, at least a chunk): the sender then
        // always has most of the window in flight — at half, a whole round trip of the
        // pipe idled at every grant
        immutable grantAt = recvWindow / 8 > streamChunk ? recvWindow / 8 : streamChunk;
        if (consumed >= grantAt && !closed_ && !remoteEnded)
        {
            recvAllowed += consumed;
            credit.send(consumed);
            consumed = 0;
        }
        return n;
    }

    /// All of `bytes`, waiting for credit as needed. Throws if the stream closes first.
    void write(scope const(ubyte)[] bytes)
    {
        if (localEnded)
            throw new Exception("stream: write after end");
        while (bytes.length)
        {
            auto c = ev.emitCount;
            while (sendCredit == 0 && !closed_ && !localEnded)
                c = ev.wait(c);
            if (closed_)
                throw new Exception("stream: closed");
            if (localEnded)
                throw new Exception("stream: ended while a write waited");
            immutable n = cast(size_t) min(bytes.length, sendCredit, streamChunk);
            if (!data.send(cast(ubyte[]) bytes[0 .. n]))
                throw new Exception("stream: closed");
            sendCredit -= n;
            bytes = bytes[n .. $];
        }
    }

    /// No more bytes from this side (the remote reads 0 once it has everything).
    void end()
    {
        if (localEnded || closed_)
            return;
        localEnded = true;
        fin.send(0);
        ev.emit();   // a write waiting for credit gives up (nothing may follow the end)
    }

    /// Tear the stream down (both directions).
    void close() nothrow
    {
        if (closed_)
            return;
        markClosed();
        try
            ch.close();
        catch (Exception)
        {
        }
    }

    /// Closed (by either side) — as opposed to ended cleanly.
    bool isClosed() const nothrow { return closed_; }

    /// The remote ended its side cleanly (its FIN arrived): once what it sent is read,
    /// `read` returns 0 for this reason rather than a close.
    bool ended() const nothrow { return remoteEnded; }

    /// Both sides ended: nothing more will flow.
    bool finished() const nothrow { return closed_ || (localEnded && remoteEnded && inq.length == 0); }
}

// ---- the TCP bridge -----------------------------------------------------------------

import vibe.core.net : TCPConnection, TCPListener, listenTCP, connectTCP;

/// Copy both ways between a TCP connection and a stream until both directions end; then
/// close both. Runs the TCP→stream half in its own task. The stream's end becomes the
/// socket's FIN (and the socket's EOF the stream's end), so a request/response protocol
/// that waits for the other side to finish still works; a stream that is CLOSED (not
/// ended) — the peer gone, the mux down — tears the socket down too.
void splice(TCPConnection tcp, ChannelStream s)
{
    import vibe.core.core : runTask;
    import core.sys.posix.sys.socket : shutdown, SHUT_WR, SHUT_RD;

    immutable fd = tcp.fd;
    // wakes the TCP→stream task if it waits for socket data when the stream closes — the
    // READ side only: what the stream already delivered is still written to the socket
    // (a peer closes right after its end; its last bytes must not be cut off)
    // A stuck socket (its client stopped reading) must not hold the splice forever: once
    // the stream is closed, the last bytes get `drainTimeout` to go, then the socket is cut.
    auto done = new bool;
    auto drain = new Task;   // the drain timer, if one runs: cancelled when the splice ends
    void onStreamClosed() nothrow
    {
        import core.sys.posix.sys.socket : SHUT_RDWR;

        if (*done)
            return;   // the splice is over: nothing to wake, no timer to leave behind
        shutdown(fd, SHUT_RD);
        if (*drain != Task.init)
            return;
        try
            *drain = runTask(() nothrow {
                try
                    sleep(drainTimeout);
                catch (Exception)
                {
                }
                if (!*done)
                    shutdown(fd, SHUT_RDWR);
            });
        catch (Exception)
        {
        }
    }
    s.onClosed = &onStreamClosed;
    if (s.isClosed)
        onStreamClosed();

    // (the connection goes in as an argument: a struct with a destructor cannot be captured)
    auto up = runTask((TCPConnection t, ChannelStream st) nothrow {
        try
        {
            ubyte[streamChunk] buf;
            while (true)
            {
                if (!t.waitForData())
                    break;
                immutable n = min(buf.length, cast(size_t) t.leastSize);
                t.read(buf[0 .. n]);
                st.write(buf[0 .. n]);
            }
            st.end();
        }
        catch (Exception)
            st.close();
    }, tcp, s);
    bool clean;
    try
    {
        ubyte[streamChunk] buf;
        while (true)
        {
            immutable n = s.read(buf[]);
            if (n == 0)
                break;
            tcp.write(buf[0 .. n]);
        }
        tcp.flush();
        clean = !s.isClosed;
    }
    catch (Exception)
    {
    }
    if (clean)
        shutdown(fd, SHUT_WR);   // the stream ended: FIN toward the socket, keep reading its answer
    else
        s.close();               // closed or failed: onClosed wakes the socket reader, it leaves
    try
        up.join();
    catch (Exception)
    {
    }
    *done = true;   // before the fd can be closed (and reused): the drain timer leaves it alone
    if (*drain != Task.init && drain.running)
        drain.interrupt();   // no timer outlives the splice
    try
        tcp.close();
    catch (Exception)
    {
    }
    s.close();
}

/// Carry every TCP connection accepted on `bindAddress:port` to the peer behind `mux()`,
/// as a stream for `service`. `mux` is asked per connection (the peer may have
/// reconnected meanwhile); null refuses. Returns the listener (stop it to stop).
TCPListener forwardTcp(Protomux delegate() mux, string service, ushort port, string bindAddress = "127.0.0.1")
{
    return listenTCP(port, (TCPConnection tcp) nothrow {
        try
        {
            auto m = mux();
            if (m is null)
            {
                tcp.close();
                return;
            }
            auto s = ChannelStream.open(m, service);
            splice(tcp, s);
        }
        catch (Exception)
        {
            try
                tcp.close();
            catch (Exception)
            {
            }
        }
    }, bindAddress);
}

/// "host:port" or "[v6]:port" → host (brackets stripped) and port. False when malformed.
bool parseHostPort(string target, out string host, out ushort port) nothrow
{
    import std.conv : to;

    ptrdiff_t k = -1;
    foreach_reverse (i, ch; target)
        if (ch == ':')
        {
            k = i;
            break;
        }
    if (k <= 0 || k + 1 >= target.length)
        return false;
    host = target[0 .. k];
    if (host.length >= 2 && host[0] == '[' && host[$ - 1] == ']')
        host = host[1 .. $ - 1];
    try
        port = target[k + 1 .. $].to!ushort;
    catch (Exception)
        return false;
    return host.length > 0 && port != 0;
}

unittest
{
    string h;
    ushort p;
    assert(parseHostPort("127.0.0.1:8000", h, p) && h == "127.0.0.1" && p == 8000);
    assert(parseHostPort("[::1]:8080", h, p) && h == "::1" && p == 8080);
    assert(!parseHostPort("nohost", h, p));
    assert(!parseHostPort("x:", h, p));
    assert(!parseHostPort("x:99999", h, p));
}

/// Answer the peer's streams on `mux`: a stream for a service in `services` (name →
/// "host:port") is connected to that address; any other is refused.
void serveTcp(Protomux mux, string[string] services)
{
    ChannelStream.accept(mux, (ChannelStream s) {
        auto target = s.service in services;
        if (target is null)
        {
            s.close();
            return;
        }
        string host;
        ushort port;
        if (!parseHostPort(*target, host, port))
        {
            s.close();
            return;
        }
        auto tcp = connectTCP(host, port, null, 0, 10.seconds);
        splice(tcp, s);
    });
}

unittest
{
    // two muxes wired to each other: open, both directions, flow control, end, refuse
    import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep, yield;

    Protomux a, b;
    ubyte[][] toA, toB;
    a = new Protomux((const(ubyte)[] f) nothrow { toB ~= f.dup; });
    b = new Protomux((const(ubyte)[] f) nothrow { toA ~= f.dup; });
    bool pumping = true;
    // the "network": frames are delivered from a task of their own, as a socket would
    runTask(() nothrow {
        while (pumping)
        {
            try
            {
                while (toA.length || toB.length)
                {
                    auto fa = toA, fb = toB;
                    toA = null;
                    toB = null;
                    foreach (f; fb)
                        b.onFrame(f);
                    foreach (f; fa)
                        a.onFrame(f);
                }
                sleep(1.msecs);
            }
            catch (Exception)
            {
            }
        }
    });

    ubyte[] big = new ubyte[3 * streamWindow + 12_345];
    foreach (i, ref x; big)
        x = cast(ubyte)(i * 31 + 7);
    ubyte[] echoed;
    string seenService;
    bool refused;
    string failure;

    ChannelStream.accept(b, (ChannelStream s) {
        seenService = s.service;
        if (s.service != "echo")
        {
            s.close();
            return;
        }
        ubyte[4096] buf;
        while (true)
        {
            immutable n = s.read(buf[]);
            if (n == 0)
                break;
            s.write(buf[0 .. n]);
        }
        s.end();
    });

    runTask(() nothrow {
        try
        {
            auto s = ChannelStream.open(a, "echo");
            auto reader = runTask(() nothrow {
                try
                {
                    ubyte[7000] buf;
                    while (true)
                    {
                        immutable n = s.read(buf[]);
                        if (n == 0)
                            break;
                        echoed ~= buf[0 .. n];
                        if (echoed.length % 50_000 < 7000)
                            sleep(2.msecs);   // a slow reader: the writer must wait for credit
                    }
                }
                catch (Exception e)
                    failure = e.msg;
            });
            s.write(big);
            s.end();
            reader.join();
            // an unknown service: the other side closes it at once — the opener reads the end
            try
            {
                auto r = ChannelStream.open(a, "nope", 2.seconds);
                ubyte[8] t;
                refused = r.read(t[]) == 0;
            }
            catch (Exception)
                refused = true;
        }
        catch (Exception e)
            failure = e.msg;
        pumping = false;
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();
    assert(failure is null, failure);
    assert(echoed == big, "echo mismatch");
    assert(refused);
    assert(seenService == "nope");
}

unittest
{
    // a receiver that widens its window: the opener writes 3 MiB before a byte is read
    import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

    Protomux a, b;
    ubyte[][] toA, toB;
    a = new Protomux((const(ubyte)[] f) nothrow { toB ~= f.dup; });
    b = new Protomux((const(ubyte)[] f) nothrow { toA ~= f.dup; });
    bool pumping = true;
    runTask(() nothrow {
        while (pumping)
        {
            try
            {
                while (toA.length || toB.length)
                {
                    auto fa = toA, fb = toB;
                    toA = null;
                    toB = null;
                    foreach (f; fb)
                        b.onFrame(f);
                    foreach (f; fa)
                        a.onFrame(f);
                }
                sleep(1.msecs);
            }
            catch (Exception)
            {
            }
        }
    });
    bool readerStarted, wroteAllFirst;
    size_t got;
    ChannelStream.accept(b, (ChannelStream s) {
        sleep(300.msecs);   // not reading yet
        readerStarted = true;
        ubyte[65536] buf;
        while (true)
        {
            immutable n = s.read(buf[]);
            if (n == 0)
                break;
            got += n;
        }
    }, 32, 3 * 1024 * 1024);
    runTask(() nothrow {
        try
        {
            auto s = ChannelStream.open(a, "wide");
            sleep(20.msecs);   // the extra credit lands
            s.write(new ubyte[3 * 1024 * 1024]);
            wroteAllFirst = !readerStarted;
            s.end();
            foreach (_; 0 .. 300)
            {
                if (got == 3 * 1024 * 1024)
                    break;
                sleep(10.msecs);
            }
        }
        catch (Exception)
        {
        }
        pumping = false;
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();
    assert(wroteAllFirst, "the widened window did not take");
    assert(got == 3 * 1024 * 1024);
}
