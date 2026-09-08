/// A D connect-by-key SERVER discoverable on a real DHT: bootstrap off a node,
/// announce ourselves (listen) so a client can find us by public key and a relay
/// forwards its PEER_HANDSHAKE to us, then accept the connection and echo. Proves
/// the D server side interoperates with a REAL hyperdht client.
/// args: <bootPort> <serverKeyFile>
module app;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.serve : Server;
import hyperswarm.connection : Connection;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import hyperswarm.cenc : Address;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.file : write;
import std.conv : to;
import std.format : format;
import std.stdio : writeln;

private __gshared Server g_server;

int main(string[] args)
{
    immutable bootPort = args[1].to!ushort;
    immutable serverKeyFile = args[2];

    runTask(() nothrow {
        try
        {
            auto dht = new Dht([Address("127.0.0.1", 4, bootPort)]);
            auto kp = ed25519RandomKeypair();
            g_server = new Server(dht, kp);
            g_server.onConnection = (Connection c) nothrow {
                try
                    writeln("OK D server accepted a connection from a real client");
                catch (Exception)
                {
                }
                c.onData = (ubyte[] m) nothrow { c.write(m); }; // echo
            };

            immutable committed = g_server.listen(); // announce-self
            writeln("D server listening: announced to ", committed, " node(s)");

            string hex;
            foreach (b; kp.publicKey)
                hex ~= format("%02x", b);
            write(serverKeyFile, hex);

            // stay up to serve; the harness kills us when the client is done
            for (int i = 0; i < 6000; i++)
                sleep(100.msecs);
        }
        catch (Exception e)
        {
            try
                writeln("FAIL ", e.msg);
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
    return 0;
}
