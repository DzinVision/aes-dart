import 'dart:typed_data';

import 'package:aes/aes.dart';
import 'package:test/test.dart';

main() {
  var padding = PKCS7();

  group('Add padding', () {
    test('partial block', () {
      var data = Uint8List.fromList([0, 1, 2, 3, 4, 5]);
      var padded = padding.add_padding(data, 16);

      expect(
          padded, [0, 1, 2, 3, 4, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]);
    });

    test('complete block', () {
      var data = Uint8List.fromList(
          [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
      var padded = padding.add_padding(data, 16);

      expect(padded, [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16
      ]);
    });
  });

  group('Remove padding', () {
    test('partial block', () {
      var data = Uint8List.fromList(
          [0, 1, 2, 3, 4, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]);
      var unpadded = padding.remove_padding(data);

      expect(unpadded, [0, 1, 2, 3, 4, 5]);
    });

    test('complete block', () {
      var data = Uint8List.fromList([
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16,
        16
      ]);

      var unpadded = padding.remove_padding(data);

      expect(unpadded, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    });
  });
}
