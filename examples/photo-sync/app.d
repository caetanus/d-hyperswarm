/// photo-sync — a peer-to-peer folder sync over the D Holepunch stack.
///
/// Two peers agree on a passphrase; its BLAKE2b/SHA-256 is the 32-byte hyperswarm
/// topic. One joins the topic in SERVER mode (announce + listen), the other in
/// CLIENT mode (lookup + connect). They meet on the REAL Holepunch DHT
/// (node{1,2,3}.hyperdht.org) — no central server of ours — hole-punch/connect,
/// bring up a Noise secret-stream over UDX, and then run a tiny bidirectional
/// sync: each side sends a manifest (name + size + content hash), asks for what it
/// is missing or what differs, and streams those files. End state: both folders
/// hold the union, byte-identical.
///
///   photo-sync server <passphrase> <folder> [host:port ...]
///   photo-sync client <passphrase> <folder> [host:port ...]
///
/// With no bootstrap args it uses the live Holepunch bootstrap. Pass one or more
/// host:port to point at a local bootstrapper instead (for hermetic testing).
module app;

import hyperswarm.swarm : Hyperswarm;
import hyperswarm.connection : Connection;
import hyperswarm.cenc : Address;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import core.time : msecs, seconds;
import std.algorithm : sort;
import std.array : appender;
import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import std.conv : to;
import std.digest.sha : sha256Of, toHexString;
import std.file : dirEntries, SpanMode, exists, read, fwrite = write, mkdirRecurse, isDir, getcwd, rename;
import std.json : JSONValue, parseJSON;
import std.path : baseName, buildPath;
import std.stdio : writeln, writefln, stdout;
import std.string : toLower;

// --- wire framing -----------------------------------------------------------------
// Every message is [4-byte BE length][1-byte type][payload]. onData is treated as a
// byte stream and reframed here, so it is robust to any chunking underneath.
private enum ubyte MANIFEST = 1; // payload: JSON {files:[{name,size,hash}]}
private enum ubyte WANT = 2;     // payload: JSON {names:[...]}
private enum ubyte FILE_CHUNK = 3; // payload: [2-byte namelen][name][1-byte last][bytes]
private enum ubyte COMPLETE = 4;   // payload: (empty) — I have sent everything you asked for

private enum size_t CHUNK = 256 * 1024;
private enum size_t MAX_FILE = 512UL * 1024 * 1024; // per file, declared and received

// A file name the peer sent is data, not a path: one plain component of the sync
// folder, nothing that could escape it (no separators, no `.`/`..`, no dotfile,
// nothing absurdly long). Everything else is dropped on the floor.
private bool safeName(string name) nothrow @safe
{
    if (name.length == 0 || name.length > 255)
        return false;
    if (name[0] == '.')
        return false; // `.`, `..`, dotfiles (and our own temp files)
    foreach (c; name)
        if (c == '/' || c == '\\' || c == '\0')
            return false;
    return true;
}

// --- one peer's whole sync state --------------------------------------------------
final class Syncer
{
    string folder;
    Connection conn;
    ubyte[] rx; // receive-side reframing buffer

    bool isServer;           // role: server waits for the client's first frame before sending
    string myManifestStr;    // my manifest JSON, computed once in begin()
    bool manifestSent;

    string[string] myHashes; // name -> content hash (my folder)
    string[] wanted;         // names I asked the peer for
    bool[string] wantedDone;  // names fully received
    string[string] wantHash;  // name -> hash the peer's manifest declared
    size_t[string] wantSize;  // name -> size the peer's manifest declared
    ubyte[][string] incoming; // name -> bytes accumulating

    bool sentComplete;   // I finished sending the peer everything it wanted
    bool peerComplete;   // the peer told me it finished sending
    bool manifestSeen;   // I received the peer's manifest
    int filesSent, filesReceived;

    this(string folder, Connection conn) nothrow
    {
        this.folder = folder;
        this.conn = conn;
    }

    // scan the folder into name -> {size, hash}
    JSONValue buildManifest() nothrow
    {
        JSONValue root;
        try
        {
            JSONValue[] files;
            foreach (e; dirEntries(folder, SpanMode.shallow))
            {
                if (e.isDir)
                    continue;
                immutable name = baseName(e.name);
                if (name.length && name[0] == '.')
                    continue; // skip dotfiles / our temp
                auto bytes = cast(ubyte[]) read(e.name);
                immutable h = toHexString(sha256Of(bytes)).idup.toLower;
                myHashes[name] = h;
                JSONValue f;
                f["name"] = name;
                f["size"] = cast(long) bytes.length;
                f["hash"] = h;
                files ~= f;
            }
            root["files"] = files;
        }
        catch (Exception ex)
            logSafe("manifest scan error: " ~ ex.msg);
        return root;
    }

    void sendFrame(ubyte type, scope const(ubyte)[] payload) nothrow
    {
        auto buf = new ubyte[](5 + payload.length);
        buf[0 .. 4] = nativeToBigEndian(cast(uint)(1 + payload.length));
        buf[4] = type;
        if (payload.length)
            buf[5 .. $] = payload[];
        conn.write(buf);
    }

    // Index the folder up front (in onConnection context, not the read callback), then:
    // the CLIENT sends its manifest immediately; the SERVER waits and replies only once the
    // client's first frame arrives (onData) — the Connection drops inbound app data that lands
    // before onData is set, so the responder must not speak first.
    void begin(bool server) nothrow
    {
        isServer = server;
        try
        {
            myManifestStr = buildManifest().toString; // also fills myHashes
            logSafe("indexed " ~ to!string(myHashes.length) ~ " file(s) in " ~ folder
                    ~ (server ? " — server, awaiting client" : " — client, sending manifest"));
            if (!server)
                sendManifest();
        }
        catch (Exception ex)
            logSafe("begin error: " ~ ex.msg);
    }

    void sendManifest() nothrow
    {
        if (manifestSent)
            return;
        manifestSent = true;
        sendFrame(MANIFEST, cast(const(ubyte)[]) myManifestStr);
    }

    // feed raw decrypted bytes, extract whole frames
    void onBytes(ubyte[] data) nothrow
    {
        rx ~= data;
        for (;;)
        {
            if (rx.length < 4)
                return;
            ubyte[4] lenb = rx[0 .. 4];
            immutable frameLen = bigEndianToNative!uint(lenb);
            // A frame is a 1-byte type plus a bounded payload; a zero length would
            // index a byte that is not there, a huge one would buffer forever. The
            // cap is generous enough for a manifest/WANT of a large directory, small
            // enough to reject garbage and near-uint.max lengths outright.
            if (frameLen < 1 || frameLen > 64 * 1024 * 1024)
            {
                logSafe("frame length " ~ to!string(frameLen) ~ " out of range; dropping the peer");
                conn.destroy();
                rx = null;
                return;
            }
            if (rx.length < 4 + frameLen)
                return;
            immutable type = rx[4];
            auto payload = rx[5 .. 4 + frameLen].dup;
            rx = rx[4 + frameLen .. $];
            dispatch(type, payload);
        }
    }

    void dispatch(ubyte type, ubyte[] payload) nothrow
    {
        try
        {
            switch (type)
            {
            case MANIFEST:
                onManifest(payload);
                break;
            case WANT:
                onWant(payload);
                break;
            case FILE_CHUNK:
                onChunk(payload);
                break;
            case COMPLETE:
                peerComplete = true;
                logSafe("peer finished sending");
                maybeDone();
                break;
            default:
                break;
            }
        }
        catch (Exception ex)
            logSafe("dispatch error: " ~ ex.msg);
    }

    void onManifest(ubyte[] payload) nothrow
    {
        manifestSeen = true;
        // Server speaks now that the client's first frame proves the stream is open both ways.
        if (isServer)
            sendManifest();
        try
        {
            auto root = parseJSON(cast(string) payload);
            string[] want;
            foreach (f; root["files"].array)
            {
                immutable name = f["name"].str;
                immutable hash = f["hash"].str;
                immutable size = f["size"].integer;
                if (!safeName(name) || hash.length != 64 || size < 0 || size > MAX_FILE)
                {
                    logSafe("manifest: skipping unsafe entry " ~ name);
                    continue;
                }
                auto mine = name in myHashes;
                if (mine is null || *mine != hash) // missing or differs
                {
                    want ~= name;
                    wantHash[name] = hash;
                    wantSize[name] = cast(size_t) size;
                }
            }
            wanted = want;
            logSafe("peer has " ~ to!string(root["files"].array.length)
                    ~ " file(s); I want " ~ to!string(want.length));
            JSONValue w;
            w["names"] = want;
            sendFrame(WANT, cast(const(ubyte)[]) w.toString);
        }
        catch (Exception ex)
            logSafe("onManifest error: " ~ ex.msg);
    }

    void onWant(ubyte[] payload) nothrow
    {
        try
        {
            auto root = parseJSON(cast(string) payload);
            foreach (n; root["names"].array)
            {
                immutable name = n.str;
                // only what OUR manifest listed: never a path the peer made up
                if (!safeName(name) || (name in myHashes) is null)
                {
                    logSafe("want: refusing " ~ name);
                    continue;
                }
                sendFile(name);
            }
        }
        catch (Exception ex)
            logSafe("onWant error: " ~ ex.msg);
        sentComplete = true;
        sendFrame(COMPLETE, null);
        maybeDone();
    }

    void sendFile(string name) nothrow
    {
        try
        {
            import std.file : getLinkAttributes, attrIsSymlink, attrIsFile;
            immutable la = getLinkAttributes(buildPath(folder, name));
            if (attrIsSymlink(la) || !attrIsFile(la))
            {
                logSafe("refusing to send " ~ name ~ ": not a regular file");
                return; // never follow a symlink out of the sync folder
            }
            auto bytes = cast(ubyte[]) read(buildPath(folder, name));
            auto nameb = cast(ubyte[])(name.dup);
            size_t off = 0;
            do
            {
                immutable end = off + CHUNK > bytes.length ? bytes.length : off + CHUNK;
                immutable last = end == bytes.length;
                ubyte[] p;
                p ~= nativeToBigEndian(cast(ushort) nameb.length)[];
                p ~= nameb;
                p ~= cast(ubyte)(last ? 1 : 0);
                p ~= bytes[off .. end];
                sendFrame(FILE_CHUNK, p);
                off = end;
            }
            while (off < bytes.length);
            filesSent++;
            logSafe("-> sent " ~ name ~ " (" ~ to!string(bytes.length) ~ " bytes)");
        }
        catch (Exception ex)
            logSafe("sendFile " ~ name ~ " error: " ~ ex.msg);
    }

    void onChunk(ubyte[] payload) nothrow
    {
        try
        {
            if (payload.length < 3)
                return;
            ubyte[2] nlb = payload[0 .. 2];
            immutable nlen = bigEndianToNative!ushort(nlb);
            if (payload.length < 3 + nlen)
                return;
            immutable name = cast(string) payload[2 .. 2 + nlen].idup;
            immutable last = payload[2 + nlen] == 1;
            auto chunk = payload[3 + nlen .. $];
            // Only a file we asked for (so: manifest-listed, safe name), never more
            // bytes than it declared, and only kept if the content hash matches.
            auto declared = name in wantSize;
            if (declared is null || (name in wantedDone) !is null)
            {
                logSafe("chunk: refusing " ~ name);
                return;
            }
            if (incoming.get(name, null).length + chunk.length > *declared)
            {
                logSafe("chunk: " ~ name ~ " exceeds its declared size; dropping");
                incoming.remove(name);
                return;
            }
            incoming[name] ~= chunk;
            if (last)
            {
                auto bytes = incoming[name];
                incoming.remove(name);
                if (bytes.length != *declared)
                {
                    logSafe("<- " ~ name ~ ": got " ~ to!string(bytes.length)
                            ~ " bytes, manifest declared " ~ to!string(*declared) ~ "; discarded");
                    return;
                }
                immutable h = toHexString(sha256Of(bytes)).idup.toLower;
                if (h != wantHash[name])
                {
                    logSafe("<- " ~ name ~ ": content hash mismatch; discarded");
                    return;
                }
                mkdirRecurse(folder);
                // write beside, then rename: a reader never sees a half file. The
                // temp name is unpredictable so a pre-planted `.part` symlink cannot
                // redirect the write out of the folder.
                import std.conv : to;
                import std.random : uniform;
                immutable tmp = buildPath(folder, ".pw-" ~ uniform!ulong().to!string(16) ~ ".part");
                fwrite(tmp, bytes);
                rename(tmp, buildPath(folder, name));
                wantedDone[name] = true;
                filesReceived++;
                logSafe("<- received " ~ name ~ " (" ~ to!string(bytes.length) ~ " bytes)");
                maybeDone();
            }
        }
        catch (Exception ex)
            logSafe("onChunk error: " ~ ex.msg);
    }

    bool receiveDone() nothrow
    {
        return peerComplete && wantedDone.length >= wanted.length;
    }

    void maybeDone() nothrow
    {
        if (sentComplete && receiveDone() && !g_done)
        {
            g_done = true;
            logSafe("SYNC COMPLETE — sent " ~ to!string(filesSent)
                    ~ ", received " ~ to!string(filesReceived) ~ " file(s)");
        }
    }
}

// --- helpers ----------------------------------------------------------------------
private __gshared bool g_done;
private __gshared Hyperswarm g_swarm;

private void logSafe(string s) nothrow
{
    try { writeln("[photo-sync] ", s); stdout.flush(); }
    catch (Exception) {}
}

private ubyte[32] topicOf(string passphrase) nothrow
{
    ubyte[32] t;
    try
    {
        auto h = sha256Of("photo-sync:" ~ passphrase);
        t[] = h[0 .. 32];
    }
    catch (Exception) {}
    return t;
}

private Address[] parseBootstrap(string[] args)
{
    Address[] bs;
    foreach (a; args)
    {
        import std.string : indexOf;
        immutable c = a.indexOf(':');
        if (c <= 0)
            continue;
        bs ~= Address(a[0 .. c], 4, a[c + 1 .. $].to!ushort);
    }
    if (bs.length == 0)
    {
        // the live Holepunch bootstrap
        bs ~= Address("node1.hyperdht.org", 4, 49737);
        bs ~= Address("node2.hyperdht.org", 4, 49737);
        bs ~= Address("node3.hyperdht.org", 4, 49737);
    }
    return bs;
}

int main(string[] args)
{
    if (args.length < 4)
    {
        writeln("usage: photo-sync <server|client> <passphrase> <folder> [host:port ...]");
        return 2;
    }
    immutable role = args[1];
    immutable passphrase = args[2];
    immutable folder = args[3];
    auto bootstrap = parseBootstrap(args[4 .. $]);
    immutable serverMode = role == "server";

    runTask(() nothrow {
        try
        {
            mkdirRecurse(folder);
            g_swarm = new Hyperswarm(bootstrap);
            immutable topic = topicOf(passphrase);
            logSafe(role ~ " on topic " ~ toHexString(topic[0 .. 6]).idup
                    ~ "… folder=" ~ folder);

            g_swarm.onDiscover = (ubyte[32] pk) nothrow {
                logSafe("discovered a peer via topic lookup: " ~ toHexString(pk[0 .. 6]).idup);
            };
            g_swarm.onConnection = (Connection c) nothrow {
                logSafe("connected to peer (secret-stream open)");
                auto s = new Syncer(folder, c);
                c.onData = (ubyte[] m) nothrow { s.onBytes(m); };
                c.onClose = () nothrow { logSafe("connection closed"); };
                // onConnection runs post-open on both paths; onOpen is unusable here (the client
                // consumes its edge in a spin-wait, the server has it wired to be onConnection).
                s.begin(serverMode);
            };

            g_swarm.join(topic, !serverMode, serverMode);
            logSafe(serverMode ? "announced topic + listening" : "looking up topic + connecting");

            // run until synced (then linger briefly so the last frames flush), or time out
            for (int i = 0; i < 6000 && !g_done; i++)
                sleep(20.msecs);
            if (g_done)
                sleep(500.msecs);
        }
        catch (Exception ex)
            logSafe("fatal: " ~ ex.msg);
        try { exitEventLoop(); } catch (Exception) {}
    });

    runEventLoop();
    return g_done ? 0 : 1;
}
