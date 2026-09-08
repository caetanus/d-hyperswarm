/// The D side of the secret-stream interop: our SecretStream (Noise XX +
/// secret-stream transport) over a vibe TCP connection, talking to the real
/// @hyperswarm/secret-stream JS echo peer. Connects, handshakes, writes a message
/// and expects it echoed. Prints "OK" (exit 0) on a clean round-trip.
///
/// This is the phase-3 acceptance: our secret-stream is wire-compatible.
///
/// args: <peerPortFile>
module app;

import hyperswarm.noise.stream : SecretStream;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : connectTCP, TCPConnection;
import vibe.core.stream : IOMode;
import core.time : msecs, seconds;
import std.file : readText, exists;
import std.string : strip;
import std.conv : to;
import std.stdio : writeln;

private enum string MESSAGE = "hello over secret-stream";

int main(string[] args)
{
    if (args.length < 2)
    {
        writeln("usage: secretstream-interop-peer <peerPortFile>");
        return 2;
    }
    immutable peerPortFile = args[1];
    int result = 1;

    runTask(() nothrow {
        try
        {
            // wait for the JS peer to publish its port
            ushort port = 0;
            for (int i = 0; i < 500 && port == 0; i++)
            {
                try
                    if (exists(peerPortFile))
                    {
                        auto s = readText(peerPortFile).strip;
                        if (s.length)
                            port = s.to!ushort;
                    }
                catch (Exception)
                {
                }
                if (port == 0)
                    sleep(20.msecs);
            }
            if (port == 0)
            {
                writeln("FAIL peer port never appeared");
                try
                    exitEventLoop();
                catch (Exception)
                {
                }
                return;
            }

            auto conn = connectTCP("127.0.0.1", port);
            auto ss = new SecretStream(true, ed25519RandomKeypair()); // initiator
            conn.write(ss.start());
            writeln("D-SS connected to port=", port);

            bool sent, gotEcho;
            auto buf = new ubyte[](64 * 1024);
            while (!gotEcho)
            {
                if (!conn.waitForData(5.seconds))
                    break; // timeout or peer closed
                immutable n = conn.read(buf, IOMode.once);
                if (n == 0)
                    break;
                auto r = ss.feed(buf[0 .. n]);
                if (r.toSend.length)
                    conn.write(r.toSend);
                foreach (m; r.messages)
                    if (cast(string) m == MESSAGE)
                        gotEcho = true;
                if (ss.opened && !sent)
                {
                    conn.write(ss.write(cast(const(ubyte)[]) MESSAGE));
                    sent = true;
                }
            }

            if (gotEcho)
            {
                writeln("OK secret-stream echo D<->JS round-tripped");
                result = 0;
            }
            else
                writeln("FAIL no echo within timeout");

            try
                conn.close();
            catch (Exception)
            {
            }
        }
        catch (Exception e)
        {
            try
                writeln("FAIL exception: ", e.msg);
            catch (Exception)
            {
            }
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();
    return result;
}
