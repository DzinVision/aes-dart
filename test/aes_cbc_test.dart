import 'dart:typed_data';

import 'package:aes/aes.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'known_answers_cbc.dart';
import 'monte_carlo_cbc.dart';
import 'multiblock_message_cbc.dart';

main() {
  group('CBC invalid inputs', () {
    test('encryption invalid input length', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      var cbc = CBC(aes, Uint8List(16));

      expect(() => cbc.encrypt(Uint8List(123)), throwsException);
    });

    test('decryption invalid input length', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      var cbc = CBC(aes, Uint8List(16));

      expect(() => cbc.decrypt(Uint8List(123)), throwsException);
    });

    test('invalid iv length', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      expect(() => CBC(aes, Uint8List(14)), throwsException);
    });
  });

  // Monte carlo tests for CBC as specified in
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
  // Test vectors from NIST:
  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
  group('AES CBC monte carlo', () {
    group('Encryption', () {
      for (int i = 0; i < encryption_monte_carlo_cbc.length; ++i) {
        var example = encryption_monte_carlo_cbc[i];

        var key = Key(Uint8List.fromList(hex.decode(example['key'])));
        var aes = AES(key);

        Uint8List iv = hex.decode(example['iv']);

        var PT = List<Uint8List>(1001);
        var CT = List<Uint8List>(1000);

        PT[0] = hex.decode(example['input']);

        for (int j = 0; j < 1000; ++j) {
          if (j == 0) {
            var cbc = CBC(aes, iv);
            CT[j] = cbc.encrypt(PT[j]);
            PT[j + 1] = iv;
          } else {
            var cbc = CBC(aes, CT[j - 1]);
            CT[j] = cbc.encrypt(PT[j]);
            PT[j + 1] = CT[j - 1];
          }
        }

        test('Encryption $i', () {
          expect(hex.encode(CT[999]), example['output']);
        });
      }
    });

    group('Decryption', () {
      for (int i = 0; i < decryption_monte_carlo_cbc.length; ++i) {
        var example = decryption_monte_carlo_cbc[i];

        var key = Key(hex.decode(example['key']));
        var aes = AES(key);

        var iv = hex.decode(example['iv']);

        var CT = List<Uint8List>(1001);
        var PT = List<Uint8List>(1000);

        CT[0] = hex.decode(example['input']);

        for (int j = 0; j < 1000; ++j) {
          if (j == 0) {
            var cbc = CBC(aes, iv);
            PT[j] = cbc.decrypt(CT[j]);
            CT[j + 1] = iv;
          } else {
            var cbc = CBC(aes, CT[j - 1]);
            PT[j] = cbc.decrypt(CT[j]);
            CT[j + 1] = PT[j - 1];
          }
        }

        test('Decryption $i', () {
          expect(hex.encode(PT[999]), example['output']);
        });
      }
    });
  });

  // Known answers test for CBC. The test is specified in the same
  // document as the previous test and test vectors can be acquired.
  // at the same URL  as the previous test.
  group('AES CBC known answers', () {
    group('GFSbox', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_cbc_gfsbox.length; ++i) {
          var example = encryption_kat_cbc_gfsbox[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_cbc_gfsbox.length; ++i) {
          var example = decryption_kat_cbc_gfsbox[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });

    group('Key Sbox', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_cbc_keysbox.length; ++i) {
          var example = encryption_kat_cbc_keysbox[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_cbc_keysbox.length; ++i) {
          var example = decryption_kat_cbc_keysbox[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });

    group('Var Key', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_cbc_varkey.length; ++i) {
          var example = encryption_kat_cbc_varkey[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_cbc_varkey.length; ++i) {
          var example = decryption_kat_cbc_varkey[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });

    group('Var Txt', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_cbc_vartxt.length; ++i) {
          var example = encryption_kat_cbc_vartxt[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.encrypt(input);

          test('Encryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });

      group('Decryption', () {
        for (int i = 0; i < decryption_kat_cbc_vartxt.length; ++i) {
          var example = decryption_kat_cbc_vartxt[i];

          var key = Key(hex.decode(example['key']));
          var aes = AES(key);

          Uint8List iv = hex.decode(example['iv']);
          var cbc = CBC(aes, iv);

          Uint8List input = hex.decode(example['input']);
          var output = cbc.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });
  });

  // Multiblock message test for CBC. The test is specified in the same
  // document as the previous test and test vectors can be acquired.
  // at the same URL as the previous test.
  group('AES CBC multiblock message', () {
    group('Encryption', () {
      for (int i = 0; i < encryption_multiblock_message_cbc.length; ++i) {
        var example = encryption_multiblock_message_cbc[i];

        var key = Key(hex.decode(example['key']));
        var aes = AES(key);

        Uint8List iv = hex.decode(example['iv']);
        var cbc = CBC(aes, iv);

        Uint8List input = hex.decode(example['input']);
        var output = cbc.encrypt(input);

        test('Encryption $i', () {
          expect(hex.encode(output), example['output']);
        });
      }
    });

    group('Decryption', () {
      for (int i = 0; i < decryption_multiblock_message_cbc.length; ++i) {
        var example = decryption_multiblock_message_cbc[i];

        var key = Key(hex.decode(example['key']));
        var aes = AES(key);

        Uint8List iv = hex.decode(example['iv']);
        var cbc = CBC(aes, iv);

        Uint8List input = hex.decode(example['input']);
        var output = cbc.decrypt(input);

        test('Decryption $i', () {
          expect(hex.encode(output), example['output']);
        });
      }
    });
  });
}
