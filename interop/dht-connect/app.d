module app;
import hyperswarm.dht.node : Dht;
import hyperswarm.dht.connect : connectHandshake;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.file : readText, exists;
import std.string : strip, split;
import std.conv : to;
import std.stdio : writeln;

private ubyte[32] fromHex(string h)
{
    ubyte[32] o;
    foreach (i; 0 .. 32)
        o[i] = cast(ubyte) h[2 * i .. 2 * i + 2].to!ubyte(16);
    return o;
}

int main(string[] args)
{
    immutable bootPort = args[1].to!ushort;
    immutable readyFile = args[2];
    int result = 1;
    runTask(() nothrow {
        try
        {
            string line;
            for (int i = 0; i < 800 && line.length == 0; i++)
            {
                try if (exists(readyFile)) line = readText(readyFile).strip;
                catch (Exception) {}
                if (line.length == 0) sleep(20.msecs);
            }
            auto parts = line.split(" ");
            immutable serverPort = parts[0].to!ushort; // == bootPort (single node)
            ubyte[32] pubkey = fromHex(parts[1]);

            auto dht = new Dht([Address("127.0.0.1", 4, bootPort)]);
            auto kp = ed25519RandomKeypair();
            auto conn = connectHandshake(dht, pubkey, kp);
            writeln("OK connect handshake completed: serverAddress=", conn.serverAddress.host, ":",
                conn.serverAddress.port, " serverUdxId=", conn.serverPayload.udx.id,
                " firewall=", conn.serverPayload.firewall);
            result = 0;
            dht.close();
        }
        catch (Exception e) { try writeln("FAIL ", e.msg); catch (Exception) {} }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
