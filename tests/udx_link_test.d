/// Proves the C↔D boundary of the UDX facade closes, and the isolation the build
/// promises: the vendored libudx is built as plain C into ONE relocatable object
/// (bin/udx_amalgam.o, by vendor/build-libudx.sh), whose only global definitions
/// are the hs_udx_* wrappers D binds; every libudx internal (udx_*) is localized
/// by the linker, and no uv_* symbol exists at all (the shim renames libuv's
/// surface to __d_hsuv_*, which hyperswarm.udx.facade provides as extern(C)).
///
/// Two checks: (1) link — referencing hs_udx_init pulls the object in, which drags
/// its __d_hsuv_* needs with it; a missing facade function would fail this binary's
/// link. (2) the symbol table of the object itself, read with `nm`: no global
/// udx_*, no uv_* anywhere, hs_udx_* present.
module tests.udx_link_test;

import fluent.asserts;
import hyperswarm.udx.udx : hs_udx_init;

@("udx: plain-C libudx links against the D facade through hs_udx_* only")
unittest
{
    auto sym = &hs_udx_init;
    (sym !is null).should.equal(true);
}

@("udx: the amalgam exports hs_udx_* only — udx_* local, no uv_* at all")
unittest
{
    import std.process : execute;
    import std.string : splitLines, strip, split;
    import std.algorithm : canFind, filter, startsWith, map;
    import std.array : array;

    auto r = execute(["nm", "bin/udx_amalgam.o"]);
    r.status.should.equal(0);
    string[] globalsDefined, uvAny;
    foreach (line; r.output.splitLines)
    {
        auto parts = line.strip.split(" ");
        if (parts.length < 2)
            continue;
        immutable type = parts[$ - 2];
        immutable name = parts[$ - 1];
        if (name.startsWith("uv_"))
            uvAny ~= name;
        // upper-case = global; T/D/B/R are definitions (U is a reference)
        if (type.length == 1 && type[0] >= 'A' && type[0] <= 'Z' && type != "U")
            globalsDefined ~= name;
    }
    uvAny.length.should.equal(0);
    globalsDefined.canFind("hs_udx_init").should.equal(true);
    globalsDefined.filter!(n => !n.startsWith("hs_udx_")).array.length.should.equal(0);
}
