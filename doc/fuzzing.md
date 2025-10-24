# Fuzzing

Building the fuzzer requires Clang and CMake.

To quickly get started fuzzing Rialo message parser using libFuzzer:

```shell
cd fuzzing
./build.sh
./run.sh
```

Initial corpus has been generated from the testcases found in the `libsol` directory.

## Code coverage

To generate a code coverage report of the fuzzer, it is possible to use `llvm-cov` (on Ubuntu: `sudo apt install llvm`):

```shell
cd fuzzing
./coverage.sh
```

These commands generate a HTML report in `fuzzing/html-coverage/index.html`.
