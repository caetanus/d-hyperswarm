// The D side of the protomux wire test against JS protomux 3.11 (peer.js).
import std.process, std.stdio, std.conv, std.algorithm;
import hyperswarm.protomux, hyperswarm.cenc;

void main()
{
    auto p = pipeProcess(["node", __FILE_FULL_PATH__[0 .. $ - "app.d".length] ~ "peer.js"], Redirect.stdin | Redirect.stdout);
    void sendFrame(const(ubyte)[] f)
    {
        ubyte[4] h = [cast(ubyte)(f.length >> 24), cast(ubyte)(f.length >> 16), cast(ubyte)(f.length >> 8), cast(ubyte) f.length];
        p.stdin.rawWrite(h[]); p.stdin.rawWrite(f); p.stdin.flush();
    }
    ubyte[][] outq;
    auto mux = new Protomux((const(ubyte)[] f) nothrow { outq ~= f.dup; });
    mux.destroyer = (string why) nothrow { try stderr.writeln("d: DESTROY ", why); catch (Exception) {} };

    string[] echoes; string hs; ulong[] counts; bool counterClosed;
    // accept the JS "counter" channel (id 0xab): answer n+1
    mux.pair("counter", [0xab], (const(ubyte)[] id) {
        auto ch = mux.createChannel("counter", [0xab]);
        Message!Uint m;
        m = ch.addMessage!Uint((ulong v, Channel c) { counts ~= v; m.send(v + 1); });
        ch.onclose = (bool remote, Channel c) { counterClosed = remote; };
        ch.open();
    });
    auto echo = mux.createChannel("echo");
    echo.onopen = (Channel c) { State s = state(0, c.handshake.length, c.handshake); hs = Utf8.decode(s); };
    auto em = echo.addMessage!Utf8((string v, Channel c) { echoes ~= v; });
    {
        State hsState;
        Utf8.preencode(hsState, "hello-from-d");
        hsState.buffer = new ubyte[hsState.end];
        Utf8.encode(hsState, "hello-from-d");
        echo.open(hsState.buffer);   // JS declared a c.string handshake
    }
    em.send("one");
    echo.cork(); em.send("two"); em.send("three"); echo.uncork();   // one batch frame

    ubyte[] inbuf;
    foreach (_; 0 .. 400)
    {
        foreach (f; outq) sendFrame(f);
        outq = null;
        if (echoes.length >= 3 && counterClosed) break;
        ubyte[4096] buf;
        auto got = p.stdout.rawRead(buf[0 .. 1]);   // blocking, byte-wise framing is fine for a test
        if (!got.length) break;
        inbuf ~= got;
        while (inbuf.length >= 4)
        {
            immutable n = (inbuf[0] << 24) | (inbuf[1] << 16) | (inbuf[2] << 8) | inbuf[3];
            if (inbuf.length < 4 + n) break;
            mux.onFrame(inbuf[4 .. 4 + n]);
            inbuf = inbuf[4 + n .. $];
        }
    }
    p.stdin.close();
    writeln("handshake: ", hs);
    writeln("echoes: ", echoes);
    writeln("counter got: ", counts, " closed by remote: ", counterClosed);
    bool ok = hs == "hello-from-js" && echoes == ["js:one", "js:two", "js:three"] && counts == [1, 3] && counterClosed;
    writeln(ok ? "PROTOMUX INTEROP PASS" : "PROTOMUX INTEROP FAIL");
    wait(p.pid);
}
