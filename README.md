# AES dart
AES implementation written in pure Dart. Implementation is based on
[FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) standard.

For now only AES-128 is supported.

The following block cipher modes are implemented:
- ECB
- CBC

Library is not yet complete. The following features are still missing:
- [ ] padding functions
- [ ] helpers for current low level methods
- [ ] examples

## Testing
Test are written based on
[Advanced Encryption Standard Algorithm Validation System(AESAVS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)
specification. Test vectors used are the ones provided by NIST and are available
[here](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES).
To run the tests execute:
```shell script
pub run test
```

## Disclaimer
This library has not been reviewed or vetted by security professionals.
