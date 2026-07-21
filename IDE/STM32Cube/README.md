# wolfCOSE STM32Cube Support

Files used by the wolfCOSE STM32Cube pack (`I-CUBE-wolfCOSE`).

- `wolfcose_test.c` / `wolfcose_test.h`: a self test that runs a `COSE_Sign1`
  ES256 sign and verify and prints the result. It is built by the pack `Test`
  component. Call `wolfCOSETest()` from your application once the clocks and
  console are initialized; it returns `0` on success.
- `default_conf.ftl`: the STM32CubeMX configuration template for the pack.

See the [STM32Cube wiki page](https://github.com/wolfSSL/wolfCOSE/wiki/STM32Cube)
for installing the pack and running wolfCOSE on a device.
