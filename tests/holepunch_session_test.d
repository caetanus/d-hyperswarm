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

// --- round-trip (client build -> server handle -> client apply) ---
private __gshared bool g_rtReplyOk;
private __gshared bool g_rtApplyOk;
private __gshared uint g_rtClientRemoteFw;
private __gshared size_t g_rtClientRemoteAddrs;
private __gshared uint g_rtServerRemoteFw;

@("holepunch session: a full client<->server round-trip converges each side's remote state")
unittest
{
    g_rtReplyOk = false;
    g_rtApplyOk = false;
    g_rtClientRemoteFw = 999;
    g_rtClientRemoteAddrs = 0;
    g_rtServerRemoteFw = 999;

    runTask(() nothrow {
        Rpc rpc;
        SocketPool pool;
        try
        {
            rpc = new Rpc(0);
            pool = new SocketPool(rpc);
            ubyte[32] secret = 9;

            // remoteFirewall seeds are each side's guess of the other (both CONSISTENT).
            auto server = new HolepunchSession(rpc, pool, secret, /*isInitiator*/ false, FW_CONSISTENT);
            auto client = new HolepunchSession(rpc, pool, secret, /*isInitiator*/ true, FW_CONSISTENT);

            // Make each side's own NAT verdict CONSISTENT with a stable external addr
            // (3 responders agreeing), so the round advertises a real firewall+address.
            foreach (i; 0 .. 3)
            {
                server.puncher.nat.add(Address("7.7.7.7", 4, 700),
                    Address("8.8.8." ~ cast(char)('0' + cast(int) i), 4, 42));
                client.puncher.nat.add(Address("3.3.3.3", 4, 300),
                    Address("4.4.4." ~ cast(char)('0' + cast(int) i), 4, 42));
            }

            // 1. Client seals a round toward the server's address.
            auto outbound = client.buildClientRound(Address("7.7.7.7", 4, 700));
            Holepunch env;
            env.id = 0;
            env.hasPeerAddress = true;
            env.peerAddress = Address("5.5.5.5", 4, 5555); // client's external (relay's view)
            env.payload = outbound;

            // 2. Server processes it and seals a reply.
            auto reply = server.handleRound(env, Address("7.7.7.7", 4, 700),
                Address("6.6.6.6", 4, 6666), /*viaOurSocket*/ false, /*isServerRelay*/ false);
            g_rtServerRemoteFw = server.puncher.remoteFirewall;

            if (!reply.isNull)
            {
                g_rtReplyOk = true;
                // 3. Client applies the server's reply.
                g_rtApplyOk = client.applyReply(reply.get, Address("5.5.5.5", 4, 5555),
                    Address("6.6.6.6", 4, 6666));
                g_rtClientRemoteFw = client.puncher.remoteFirewall;
                g_rtClientRemoteAddrs = client.puncher.remoteAddresses.length;
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

    g_rtServerRemoteFw.should.equal(FW_CONSISTENT); // server learned the client's verdict
    g_rtReplyOk.should.equal(true);
    g_rtApplyOk.should.equal(true);
    g_rtClientRemoteFw.should.equal(FW_CONSISTENT); // client learned the server's verdict
    g_rtClientRemoteAddrs.should.be.greaterThan(cast(size_t) 0); // + its advertised address
}

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
