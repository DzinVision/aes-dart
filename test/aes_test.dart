import 'dart:typed_data';

import 'package:aes/aes.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'known_answers_ecb.dart';
import 'monte_carlo_ecb.dart';

main() {
  group('AES invalid inputs', () {
    test('empty input', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      expect(() => aes.encrypt(Uint8List(0)), throwsException);
    });

    test('invalid length (too short)', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      expect(() => aes.encrypt(Uint8List(15)), throwsException);
    });

    test('invalid length (too long)', () {
      var key = Key(Uint8List(16));
      var aes = AES(key);
      expect(() => aes.encrypt(Uint8List(123)), throwsException);
    });
  });

  group('AES example in FIPS 197 document', () {
    var key =
        Key(Uint8List.fromList(hex.decode('000102030405060708090a0b0c0d0e0f')));
    var aes = AES(key);

    test('encryption', () {
      var plaintext =
          Uint8List.fromList(hex.decode('00112233445566778899aabbccddeeff'));
      var encrypted = aes.encrypt(plaintext);
      expect(hex.encode(encrypted), '69c4e0d86a7b0430d8cdb78070b4c55a');
    });

    test('decryption', () {
      var ciphertext =
          Uint8List.fromList(hex.decode('69c4e0d86a7b0430d8cdb78070b4c55a'));
      var decrypted = aes.decrypt(ciphertext);
      expect(hex.encode(decrypted), '00112233445566778899aabbccddeeff');
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

        var data = Uint8List.fromList(hex.decode(example['input']));
        for (int j = 0; j < 1000; ++j) {
          data = aes.encrypt(data);
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

        var data = Uint8List.fromList(hex.decode(example['input']));
        for (int j = 0; j < 1000; ++j) {
          data = aes.decrypt(data);
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
  group('AES CBC known answers', () {
    group('GFSbox', () {
      group('Encryption', () {
        for (int i = 0; i < encryption_kat_ecb_gfsbox.length; ++i) {
          var example = encryption_kat_ecb_gfsbox[i];

          var key = Key(Uint8List.fromList(hex.decode(example['key'])));
          var aes = AES(key);

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.encrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.decrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.encrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.decrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.encrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.decrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.encrypt(input);

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

          var input = Uint8List.fromList(hex.decode(example['input']));
          var output = aes.decrypt(input);

          test('Decryption $i', () {
            expect(hex.encode(output), example['output']);
          });
        }
      });
    });
  });
}
