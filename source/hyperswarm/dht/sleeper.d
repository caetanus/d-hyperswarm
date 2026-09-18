/// Interruptible pause — port of hyperdht/lib/sleeper.js. A background punch loop
/// sleeps between beacons via pause(); resume() (called on connect or destroy)
/// wakes it immediately so the loop notices punching==false and exits at once
/// instead of waiting out the interval. Only one pause is ever in flight per
/// Sleeper (one loop fiber owns it), so a single manual event suffices.
module hyperswarm.dht.sleeper;

import core.time : Duration;

import vibe.core.sync : LocalManualEvent, createManualEvent;

final class Sleeper
{
    private LocalManualEvent ev;

    this()
    {
        ev = createManualEvent();
    }

    /// Sleep for `d`, or until resume() fires, whichever comes first.
    void pause(Duration d) nothrow
    {
        try
        {
            immutable cnt = ev.emitCount;
            ev.wait(d, cnt);
        }
        catch (Exception)
        {
        }
    }

    /// Wake the current pause() immediately (if any).
    void resume() nothrow
    {
        try
            ev.emit();
        catch (Exception)
        {
        }
    }
}
