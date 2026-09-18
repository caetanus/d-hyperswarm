/// Holepunch Stage D: the Holepuncher's CONSISTENT×CONSISTENT path end to end on
/// loopback. Two punchers (an initiator and a responder), each on its own Rpc/udx
/// with a fresh pool socket, aim their beacons at each other's bound port. The
/// initiator fires immediately, the responder reflects, and the initiator's
/// onConnect proves the hole opened — no real NAT needed for this leg (that's the
/// rig's job in Stage F). Assertions run AFTER runEventLoop, never in a fiber.
module tests.holepuncher_test;

import fluent.asserts;
import core.time : msecs;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.holepuncher : Holepuncher;
import hyperswarm.dht.connect_messages : FW_CONSISTENT;

private __gshared bool g_initiatorConnected;
private __gshared bool g_aborted;
private __gshared string g_connectHost;
private __gshared ushort g_connectPort;
private __gshared ushort g_responderPort;

@("holepuncher: CONSISTENT x CONSISTENT punches through on loopback")
unittest
{
    g_initiatorConnected = false;
    g_aborted = false;
    g_connectHost = null;
    g_connectPort = 0;

    runTask(() nothrow {
        Rpc rpcA, rpcB;
        SocketPool poolA, poolB;
        Holepuncher hpA, hpB;
        try
        {
            rpcA = new Rpc(0);
            rpcB = new Rpc(0);
            poolA = new SocketPool(rpcA);
            poolB = new SocketPool(rpcB);

            hpA = new Holepuncher(rpcA, poolA, /*isInitiator*/ true, FW_CONSISTENT);
            hpB = new Holepuncher(rpcB, poolB, /*isInitiator*/ false, FW_CONSISTENT);

            immutable portA = poolA.boundPort(hpA.socket());
            immutable portB = poolB.boundPort(hpB.socket());
            g_responderPort = portB;

            hpA.localFirewall = FW_CONSISTENT;
            hpB.localFirewall = FW_CONSISTENT;

            hpA.onConnect = (void* sock, Address from) nothrow {
                g_initiatorConnected = true;
                g_connectHost = from.host;
                g_connectPort = from.port;
            };
            hpA.onAbort = () nothrow { g_aborted = true; };

            // Point each at the other's loopback mapping, pre-verified.
            hpA.updateRemote(true, FW_CONSISTENT, [Address("127.0.0.1", 4, portB)], "127.0.0.1");
            hpB.updateRemote(true, FW_CONSISTENT, [Address("127.0.0.1", 4, portA)], "127.0.0.1");

            hpB.punch();
            hpA.punch();

            // Poll up to ~2s for the initiator to connect.
            foreach (_; 0 .. 100)
            {
                if (g_initiatorConnected)
                    break;
                sleep(20.msecs);
            }
        }
        catch (Exception)
        {
        }

        try
        {
            if (hpA !is null)
                hpA.destroy();
            if (hpB !is null)
                hpB.destroy();
            if (rpcA !is null)
                rpcA.close();
            if (rpcB !is null)
                rpcB.close();
        }
        catch (Exception)
        {
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();

    g_initiatorConnected.should.equal(true);
    g_aborted.should.equal(false);
    g_connectHost.should.equal("127.0.0.1");
    g_connectPort.should.equal(g_responderPort); // beacon came from the responder's socket
}
