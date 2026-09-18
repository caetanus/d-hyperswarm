/// Holepunch Stage E1: the server-side PEER_HOLEPUNCH round-step (holepunch_session.d)
/// in isolation — a synthetic client round message sealed under the shared secret is
/// fed to the session; assert it updates the puncher's remote state and seals a reply
/// the client can open. No relay/handshake wiring, no network sends (the server's NAT
/// stays UNKNOWN so no fast-open ping / punch strategy fires). Asserts after runEventLoop.
module tests.holepunch_session_test;

import fluent.asserts;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;

import hyperswarm.cenc : Address;
import hyperswarm.dht.rpc : Rpc;
import hyperswarm.dht.socket_pool : SocketPool;
import hyperswarm.dht.secure_payload : SecurePayload;
import hyperswarm.dht.holepunch_session : HolepunchSession;
import hyperswarm.dht.connect_messages : Holepunch, HolepunchPayload, decodeHolepunch,
    FW_CONSISTENT, FW_UNKNOWN, ERR_NONE;

private __gshared bool g_replyPresent;
private __gshared bool g_replyDecrypts;
private __gshared uint g_replyError;
private __gshared uint g_remoteFirewall;
private __gshared bool g_remotePunching;
private __gshared size_t g_remoteAddrCount;
private __gshared bool g_tokenEchoed;

@("holepunch session: server round updates remote state and seals an openable reply")
unittest
{
    g_replyPresent = false;
    g_replyDecrypts = false;
    g_replyError = 999;
    g_remoteFirewall = 999;
    g_remotePunching = false;
    g_remoteAddrCount = 0;
    g_tokenEchoed = false;

    runTask(() nothrow {
        Rpc rpc;
        SocketPool pool;
        try
        {
            rpc = new Rpc(0);
            pool = new SocketPool(rpc);

            ubyte[32] secret = 5;
            auto server = new HolepunchSession(rpc, pool, secret, /*isInitiator*/ false, FW_UNKNOWN);
            auto clientSeal = new SecurePayload(secret); // client shares the holepunchSecret

            // The client's round message: it's CONSISTENT, punching, advertising an addr.
            HolepunchPayload cp;
            cp.firewall = FW_CONSISTENT;
            cp.round = 0;
            cp.punching = true;
            cp.addresses = [Address("1.2.3.4", 4, 5000)];

            Holepunch env;
            env.id = 0;
            env.hasPeerAddress = true;
            env.peerAddress = Address("9.9.9.9", 4, 4242); // client's external (relay's view)
            env.payload = clientSeal.encrypt(cp);

            // reqTo = our external as the relay saw us; reqFrom = the relay.
            auto reply = server.handleRound(env, Address("2.2.2.2", 4, 1111),
                Address("3.3.3.3", 4, 2222), /*viaOurSocket*/ true, /*isServerRelay*/ false);

            g_remoteFirewall = server.puncher.remoteFirewall;
            g_remotePunching = server.puncher.remoteHolepunching;
            g_remoteAddrCount = server.puncher.remoteAddresses.length;

            if (!reply.isNull)
            {
                g_replyPresent = true;
                auto opened = clientSeal.decrypt(reply.get); // client opens the server's reply
                if (!opened.isNull)
                {
                    g_replyDecrypts = true;
                    g_replyError = opened.get.error;
                    // server not a relay here, so it must NOT echo a token
                    g_tokenEchoed = opened.get.token.length != 0;
                }
            }
        }
        catch (Exception)
        {
        }
        try
        {
            if (rpc !is null)
                rpc.close();
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

    g_replyPresent.should.equal(true);
    g_replyDecrypts.should.equal(true); // the client can open the server's sealed reply
    g_replyError.should.equal(ERR_NONE);
    g_remoteFirewall.should.equal(FW_CONSISTENT); // updateRemote took the client's verdict
    g_remotePunching.should.equal(true);
    g_remoteAddrCount.should.equal(cast(size_t) 1);
    g_tokenEchoed.should.equal(false); // not a server relay -> no token echo
}
