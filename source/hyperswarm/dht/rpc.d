/// The dht-rpc RPC layer over vibe UDP: send a request datagram with a fresh
/// transaction id and await the matching reply. A reader fiber decodes incoming
/// replies and wakes the waiting request by tid. Requests are plain UDP (a udx
/// socket's send is a UDP send), so vibe's UDPConnection is all we need.
module hyperswarm.dht.rpc;

import hyperswarm.dht.wire;
import hyperswarm.cenc : Address;
import vibe.core.net : UDPConnection, NetworkAddress, listenUDP, resolveHost;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.core : runTask;
import core.time : Duration, seconds;

final class Rpc
{
    private UDPConnection sock;
    private ushort nextTid = 1;
    private bool running;

    private static final class Pending
    {
        LocalManualEvent ev;
        Reply reply;
        bool got;
    }

    private Pending[ushort] pending;

    this(ushort bindPort = 0)
    {
        sock = listenUDP(bindPort, "0.0.0.0");
        running = true;
        runTask(&readerLoop);
    }

    ushort localPort()
    {
        return sock.localAddress.port;
    }

    void close()
    {
        running = false;
        try
            sock.close();
        catch (Exception)
        {
        }
    }

    /// Send `command` to `to` and wait for the reply (throws on timeout). `internal`
    /// marks a built-in dht-rpc command (FIND_NODE, PING); hyperdht commands
    /// (LOOKUP, ANNOUNCE, PEER_HANDSHAKE) are external — pass internal=false and, when
    /// committing, the token from that node's earlier reply.
    Reply request(Address to, uint command, scope const(ubyte)[] target = null,
        scope const(ubyte)[] value = null, scope const(ubyte)[] token = null,
        bool internal = true, Duration timeout = 2.seconds)
    {
        immutable tid = nextTid++;
        if (nextTid == 0)
            nextTid = 1;

        auto p = new Pending;
        p.ev = createManualEvent();
        pending[tid] = p;
        scope (exit)
            pending.remove(tid);

        auto req = encodeRequest(tid, to, command, target, value, token, null, internal);
        auto dst = resolveHost(to.host);
        dst.port = to.port;

        immutable cnt = p.ev.emitCount;
        sock.send(req, &dst);
        p.ev.wait(timeout, cnt);
        if (!p.got)
            throw new Exception("dht: request timed out");
        return p.reply;
    }

    private void readerLoop() nothrow
    {
        auto buf = new ubyte[](2048);
        while (running)
        {
            ubyte[] got;
            try
                got = sock.recv(buf);
            catch (Exception)
                break; // closed
            if (got.length < 2 || got[0] != RESPONSE_ID)
                continue;
            Reply r;
            try
                // dup: decoded fields slice into the packet, and `buf` is reused by
                // the next recv — the reply must own its bytes past this iteration.
                r = decodeReply(got.dup);
            catch (Exception)
                continue;
            if (auto pp = r.tid in pending)
            {
                auto p = *pp;
                p.reply = r;
                p.got = true;
                try
                    p.ev.emit();
                catch (Exception)
                {
                }
            }
        }
    }
}
