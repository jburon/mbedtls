# mbed TLS

mbed TLS (formerly known as PolarSSL) makes it trivially easy for developers to include cryptographic and SSL/TLS capabilities in their embedded products, with a minimal code footprint. It offers an SSL library with an intuitive API and readable source code.

The Beta release of mbed TLS integrates the mbed TLS library into mbed OS, mbed SDK and yotta. This is a preview release intended for evaluation only and is **not recommended for deployment**. It currently implements no secure source of random numbers, weakening its security.

Currently the only supported yotta targets are:
- `frdm-k64f-gcc` and `frdm-k64f-armcc`
- `x86-linux-native` and `x86-osx-native`

## Sample programs

This release includes the following examples:

1. [**Self test:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-selftest) found in `test/example-selftest`. Tests different basic functions in the mbed TLS library.

2. [**Benchmark:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-benchmark) found in `test/example-benchmark`. Measures the time taken to perform basic cryptographic functions used in the library.

3. [**Hashing:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-hashing) found in `test/example-hashing`. Demonstrates the various APIs for computes hashes of data (also known as message digests) with SHA-256.

4. [**Authenticated encrypted:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-authcrypt) found in `test/example-authcrypt`. Demonstrates usage of the Cipher API for encrypting and authenticating data with AES-CCM.

These examples are integrated as yotta tests, so that they are built automatically when you build mbed TLS. Each of them comes with complete usage instructions as a Readme file in its directory.

## Performing TLS and DTLS connections

A high-level API for performing TLS and DTLS connections with mbed TLS in mbed OS is provided in a separate yotta module: [mbed-tls-sockets](https://github.com/ARMmbed/mbed-tls-sockets). It is the recommended API for TLS and DTLS connections.  It is very similar to the API provided by the [sockets](https://github.com/ARMmbed/sockets) module for unencrypted TCP and UDP connections.

The `mbed-tls-sockets` module includes a complete [example TLS client](https://github.com/ARMmbed/mbed-tls-sockets/blob/master/test/tls-client/main.cpp) with [usage instructions](https://github.com/ARMmbed/mbed-tls-sockets/blob/master/test/tls-client/README.md).

## Configuring mbed TLS features

mbed TLS makes it easy to disable any feature during compilation that isn't required for a particular project. The default configuration enables all modern and widely-used features, which should meet the needs of new projects, and disables all features that are older or less common, to minimize the code footprint.

The list of available compilation flags is presented in the fully documented [config.h file](https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/config.h), present in the `mbedtls` directory of the yotta module.

If you need to adjust those flags, you can provide your own configuration-adjustment file with suitable `#define` and `#undef` statements. These will be included between the default definitions and the sanity checks. Your configuration file should be in your application's include directory, and can be named freely; you just need to let mbed TLS know the file's name. To do that, use yotta's [configuration system](http://docs.yottabuild.org/reference/config.html). The file's name should be in your `config.json` file, under mbedtls, as the key `user-config-file`.

For example, in an application called `myapp`, if you want to enable the EC J-PAKE key exchange and disable the CBC cipher mode, you can create a file named for example `mbedtls-config-changes.h` in the `myapp` directory containing the following lines:

    #define MBEDTLS_ECJPAKE_C
    #define MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED

    #undef MBEDTLS_CIPHER_MODE_CBC

and then create a file named `config.json` at the root of your application with the following contents:

    {
       "mbedtls": {
          "user-config-file": "\"myapp/mbedtls-config-changes.h\""
       }
    }

Please note: you need to provide the exact name that will be used in the `#include` directive, including the `<>` or quotes around the name.

## Contributing

We gratefully accept bug reports and contributions from the community. There are some requirements we need to fulfill in order to be able to integrate contributions:

* Simple bug fixes to existing code do not contain copyright themselves and we can integrate without issue. The same is true of trivial contributions.

* For larger contributions, such as a new feature, the code can possibly fall under copyright law. We then need your consent to share in the ownership of the copyright. We have a form for this, which we will send to you in case you submit a contribution or pull request that we deem this necessary for.

To contribute, please:

* [Check for open issues](https://github.com/ARMmbed/mbedtls/issues) or [start a discussion](https://tls.mbed.org/discussions) around a feature idea or a bug.

* Fork the [mbed TLS repository on GitHub](https://github.com/ARMmbed/mbedtls) to start making your changes. As a general rule, you should use the "development" branch as a basis.

* Write a test that shows that the bug was fixed or that the feature works as expected.

* Send a pull request and bug us until it gets merged and published. We will include your name in the ChangeLog :)