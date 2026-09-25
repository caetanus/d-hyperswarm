/// unit-threaded entry point. Test modules are listed explicitly so reflection
/// stays fast and the build stays deterministic. Test modules import
/// `fluent.asserts` only — never `unit_threaded`, whose `should` collides.
import unit_threaded;
import std.concurrency : scheduler;

int main(string[] args)
{
    // vibe-core installs its own std.concurrency Scheduler in a module ctor.
    // unit-threaded serialises output through a std.concurrency thread that,
    // under vibe's scheduler, parks in the event loop and is never woken. Hand
    // std.concurrency back its default scheduler; vibe's own task scheduler and
    // eventcore driver are untouched, so tests still drive the loop explicitly.
    scheduler = null;

    return args.runTests!(
        "tests.cenc_test",
        "tests.udx_link_test",
        "tests.uv_timer_test",
        "tests.uv_udp_test",
        "tests.udx_echo_test",
        "tests.udx_ttl_test",
        "tests.noise_crypto_test",
        "tests.noise_hs_test",
        "tests.secretstream_test",
        "tests.dht_wire_test",
        "tests.dht_table_test",
        "tests.hdht_messages_test",
        "tests.connect_messages_test",
        "tests.holepunch_messages_test",
        "tests.noise_wrap_test",
        "hyperswarm.connection",
        "tests.connection_drain_test",
        "tests.socket_pool_test",
        "tests.nat_test",
        "tests.secure_payload_test",
        "tests.holepuncher_test",
        "tests.random_punch_test",
        "tests.holepunch_session_test",
        "tests.close_test",
        "tests.punch_handoff_test",
    );
}
