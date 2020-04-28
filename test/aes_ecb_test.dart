import 'dart:typed_data';

import 'package:aes/aes.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'known_answers_ecb.dart';
import 'monte_carlo_ecb.dart';
import 'multiblock_message_ecb.dart';

main() {
  group('ECB invalid inputs', () {
    test('invalid length', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      var ecb = ECB(aes);

      expect(() => ecb.encrypt(Uint8List(123)), throwsException);
    });
  });

  // Monte carlo tests for ECB as specified in
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
  // Test vectors from NIST:
  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
  group('AES ECB monte carlo', () {
    group('Encryption', () {
      for (int i = 0; i < encryption_monte_carlo_ecb.length; ++i) {
        var example = encryption_monte_carlo_ecb[i];

        var key = Key(Uint8List.fromList(hex.decode(example['key'])));
        var aes = AES(key);
        var ecb = ECB(aes);

        var data = Uint8List.fromList(hex.decode(example['input']));
        for (int j = 0; j < 1000; ++j) {
          data = ecb.encrypt(data);
        }

        test('Encryption $i', () {
          expect(hex.encode(data), example['output']);
        });
      }
    });

    group('Decryption', () {
      for (int i = 0; i < decryption_monte_carlo_ecb.length; ++i) {
        var example = decryption_monte_carlo_ecb[i];

        var key = Key(Uint8List.fromList(hex.decode(example['key'])));
        var aes = AES(key);
        var ecb = ECB(aes);

        var data = Uint8List.fromList(hex.decode(example['input']));
        for (int j = 0; j < 1000; ++j) {
          data = ecb.decrypt(data);
        }

        test('Decryption $i', () {
          expect(hex.encode(data), example['output']);
        });
      }
    });
  });

  // Known answers test for ECB. The test is specified in the same
  // document as the previous test and test vectors can be acquired.
  // at the same URL  as the previous test.
  group('AES ECB known answers', () {
    group('GFSbox', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_ecb_gfsbox.length; ++i) {
          var example = encryption_kat_ecb_gfsbox[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_ecb_gfsbox.length; ++i) {
          var example = decryption_kat_ecb_gfsbox[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });

    group('Key Sbox', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_ecb_keysbox.length; ++i) {
          var example = encryption_kat_ecb_keysbox[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_ecb_keysbox.length; ++i) {
          var example = decryption_kat_ecb_keysbox[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });

    group('Var Key', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_ecb_varkey.length; ++i) {
          var example = encryption_kat_ecb_varkey[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_ecb_varkey.length; ++i) {
          var example = decryption_kat_ecb_varkey[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });

    group('Var Txt', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_ecb_vartxt.length; ++i) {
          var example = encryption_kat_ecb_vartxt[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_ecb_vartxt.length; ++i) {
          var example = decryption_kat_ecb_vartxt[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);
          var ecb = ECB(aes);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = ecb.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });
  });

  // Multiblock message test for ECB. The test is specified in the same
  // document as the previous test and test vectors can be acquired.
  // at the same URL as the previous test.
  group('AES ECB multiblock message', () {
    group('Encryption', () {
      for (int i = 0; i < encryption_multiblock_message_ecb.length; ++i) {
        var example = encryption_multiblock_message_ecb[i];

        var key = Key(Uint8List.fromList(hex.decode(example['key'])));
        var aes = AES(key);
        var ecb = ECB(aes);

        var input = Uint8List.fromList(hex.decode(example['input']));
        var output = ecb.encrypt(input);

        test('Encryption $i', () {
          expect(hex.encode(output), example['output']);
        });
      }
    });

    group('Decryption', () {
      for (int i = 0; i < decryption_multiblock_message_ecb.length; ++i) {
        var example = decryption_multiblock_message_ecb[i];

        var key = Key(Uint8List.fromList(hex.decode(example['key'])));
        var aes = AES(key);
        var ecb = ECB(aes);

        var input = Uint8List.fromList(hex.decode(example['input']));
        var output = ecb.decrypt(input);

        test('Decryption $i', () {
          expect(hex.encode(output), example['output']);
        });
      }
    });
  });
}
