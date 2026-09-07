/// First behaviour of the libuv→vibe facade: a timer registered through the
/// `hsuv_*` API fires on the vibe event loop, driven by `Loop.run`. This is the
/// run model libudx's RTO/keepalive/pacing timers will ride on.
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body (calling
/// fluent-asserts' `.should` on a fiber stack has crashed the harness before).
module tests.uv_timer_test;

import fluent.asserts;
import hyperswarm.udx.facade;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs, MonoTime;

private __gshared int g_oneShotFires;
private __gshared int g_repeatFires;
private __gshared MonoTime g_firedAt;
private __gshared MonoTime g_started;

extern (C) void onOneShot(uv_handle_t* h) nothrow
{
    g_oneShotFires++;
    g_firedAt = MonoTime.currTime;
}

extern (C) void onRepeat(uv_handle_t* h) nothrow
{
    g_repeatFires++;
    if (g_repeatFires >= 3)
    {
        try
            hsuv_timer_stop(h);
        catch (Exception)
        {
        }
    }
}

@("uv facade: a one-shot timer fires once on the vibe loop, after its timeout")
unittest
{
    g_oneShotFires = 0;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();
            auto t = new uv_timer_t;
            hsuv_timer_init(loop.chandle, t);
            g_started = MonoTime.currTime;
            hsuv_timer_start(t, &onOneShot, 40, 0);

            runTask(() nothrow { try loop.run(); catch (Exception) {} });

            sleep(160.msecs);
            loop.stop();
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

    g_oneShotFires.should.equal(1); // fired exactly once (one-shot, not re-armed)
    immutable elapsed = (g_firedAt - g_started).total!"msecs";
    (elapsed >= 30).should.equal(true); // did not fire before its timeout
}

@("uv facade: a repeating timer re-arms until stopped")
unittest
{
    g_repeatFires = 0;

    runTask(() nothrow {
        try
        {
            auto loop = new Loop();
            auto t = new uv_timer_t;
            hsuv_timer_init(loop.chandle, t);
            hsuv_timer_start(t, &onRepeat, 20, 20); // repeat every 20ms

            runTask(() nothrow { try loop.run(); catch (Exception) {} });

            sleep(200.msecs);
            loop.stop();
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

    // Stopped itself at 3; must not have kept firing past that in ~200ms.
    g_repeatFires.should.equal(3);
}
