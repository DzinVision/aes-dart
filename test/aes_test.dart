import 'dart:typed_data';

import 'package:aes/aes.dart';
import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'monte_carlo.dart';

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

  // Monte carlo tests as specified in
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
  // Test vectors from NIST:
  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
  group('AES monte carlo', () {
    group('Encryption', () {
      for (int i = 0; i < encryption_monte_carlo.length; ++i) {
        var example = encryption_monte_carlo[i];

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
      for (int i = 0; i < decryption_monte_carlo.length; ++i) {
        var example = decryption_monte_carlo[i];

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
}
