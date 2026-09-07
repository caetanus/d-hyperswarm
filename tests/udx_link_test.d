/// Proves the C++↔D boundary of the UDX facade closes: the amalgamated libudx
/// archive (bin/libhsudx.a — one C++ TU in `namespace udx`, built by the
/// preBuildCommand) links into the test binary, and its every `hsuv_*` reference
/// is resolved by hyperswarm.udx.facade. Referencing a `udx::` symbol pulls the
/// archive in, which drags its hsuv_* needs with it; if any facade function were
/// missing, or the archive failed to build/link, this binary would not link.
///
/// The whole public API is now enclosed under `udx::` (the extern "C" guard in
/// udx.h is disabled for the C++ build), so we reference the mangled symbol
/// directly. This is the link milestone — no behaviour is exercised (the facade
/// stubs would assert if called). The real binding will declare the udx:: API with
/// mirrored types via extern(C++, "udx"); here pragma(mangle) names one symbol
/// exactly, which is all the link proof needs.
module tests.udx_link_test;

import fluent.asserts;

// udx::udx_init(uv_loop_s*, udx::udx_s*, void(*)(udx::udx_s*)) — the mangled name
// from the amalgamation. Declared bodyless purely to demand the symbol at link.
pragma(mangle, "_ZN3udx8udx_initEP9uv_loop_sPNS_5udx_sEPFvS3_E")
extern (C++) void udx_init_symbol();

@("udx: amalgamated libudx (namespace udx) links against the D facade")
unittest
{
    auto sym = &udx_init_symbol;
    (sym !is null).should.equal(true);
}
