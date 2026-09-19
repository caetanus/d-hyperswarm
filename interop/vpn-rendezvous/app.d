/// vpn-rendezvous — serverless peer discovery for the WireGuard-over-libp2p VPN.
/// Two peers that share a secret announce their punch srflx under a topic derived
/// from it (on the live hyperdht) and look each other up — no manual paste, no
/// signaling server. Prints "PEER <ip> <port> ROLE <dialer|listener>" for the vpn
/// to punch with (WG keys + libp2p identity are derived from the same secret, so
/// only the srflx needs exchanging). Roles are decided deterministically from the
/// two DHT pubkeys so both agree.
///
///   vpn-rendezvous --secret <s> --srflx-ip <ip> --srflx-port <p>
module app;

import std.stdio : writeln, stderr;
import std.getopt : getopt;
import std.digest.sha : sha256Of;
import core.time : msecs, seconds, MonoTime;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.dht.node : Dht;
import hyperswarm.dht.messages : PeerRecord;
import hyperswarm.noise.crypto : ed25519RandomKeypair;
import hyperswarm.cenc : Address;

__gshared string g_secret;
__gshared string g_srflxIp;
__gshared ushort g_srflxPort;

// bytewise compare of two 32-byte keys
private int cmp32(const ubyte[32] a, const ubyte[32] b)
{
    foreach (i; 0 .. 32)
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    return 0;
}

int main(string[] args)
{
    getopt(args, "secret", &g_secret, "srflx-ip", &g_srflxIp, "srflx-port", &g_srflxPort);
    int result = 1;
    runTask(() nothrow {
        try
        {
            Address[] boot = [
                Address("node1.hyperdht.org", 4, 49737),
                Address("node2.hyperdht.org", 4, 49737),
                Address("node3.hyperdht.org", 4, 49737)
            ];
            auto dht = new Dht(boot);
            auto kp = ed25519RandomKeypair();
            ubyte[32] topic = sha256Of("wgvpn-rendezvous:" ~ g_secret);
            auto myAddr = Address(g_srflxIp, 4, g_srflxPort);

            immutable deadline = MonoTime.currTime + 90.seconds;
            while (MonoTime.currTime < deadline && result != 0)
            {
                dht.announce(topic, kp, [myAddr]);
                sleep(400.msecs);
                foreach (p; dht.lookup(topic))
                {
                    if (p.publicKey == kp.publicKey)
                        continue;
                    if (p.relayAddresses.length == 0)
                        continue;
                    auto pa = p.relayAddresses[0];
                    immutable role = cmp32(kp.publicKey, p.publicKey) < 0 ? "dialer" : "listener";
                    writeln("PEER ", pa.host, " ", pa.port, " ROLE ", role);
                    result = 0;
                    break;
                }
                if (result != 0)
                    sleep(1200.msecs);
            }
            if (result != 0)
                writeln("FAIL: peer not found under the shared topic");
            dht.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("vpn-rendezvous error: ", e.msg);
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
