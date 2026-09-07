/// unit-threaded entry point. Test modules are listed explicitly so reflection
/// stays fast and the build stays deterministic. Test modules import
/// `fluent.asserts` only — never `unit_threaded`, whose `should` collides.
import unit_threaded;

int main(string[] args)
{
    return args.runTests!(
        "tests.cenc_test",
    );
}
