/// Proves the C↔D boundary of the UDX facade closes: the vendored libudx archive
/// (bin/libhsudx.a, built by the preBuildCommand) links into the test binary, its
/// every `hsuv_*` reference is resolved by hyperswarm.udx.facade, and a libudx
/// symbol is reachable from D. If any facade function were missing, or the archive
/// failed to build/link, this binary would not link at all.
///
/// This is the link milestone — no behaviour is exercised (the facade stubs would
/// assert if called); referencing `&udx_init` is enough to demand the symbol and,
/// with it, the whole udx dependency graph and its hsuv_* needs.
module tests.udx_link_test;

import fluent.asserts;

// One entry point from the vendored C. Typed loosely (void*) — this milestone is
// about linkage, not calling into udx.
extern (C) int udx_init(void* loop, void* udx, void* on_idle);

@("udx: vendored libudx links against the D facade (hsuv_* all resolved)")
unittest
{
    auto sym = &udx_init;
    (sym !is null).should.equal(true);
}
