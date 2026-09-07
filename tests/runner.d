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
    );
}
