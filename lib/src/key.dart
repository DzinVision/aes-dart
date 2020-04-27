import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'const.dart';

class KeyLengthException implements Exception {
  String errMsg() => 'Key is of invalid length.';
}

class Key {
  // Number of words in key. For AES 128 there are 4 words in a key.
  static const int _Nk = 4;

  // Number of columns comprising a state in AES. This is constant of 4.
  static const int _Nb = 4;

  // Number of rounds of expantion. For AES-128 this is 10.
  static const _ROUNDS = 10;

  // Final expended key.
  Uint8List _expanded_key;

  Key(Uint8List initial_key) {
    _expand_key(initial_key);
  }

  // Expands the initial key to satisfy the length
  // needed for _rounds rounds.
  void _expand_key(Uint8List initial_key) {
    // Check that the size of the initial key is correct.
    if (initial_key.length != 4 * _Nk) {
      throw KeyLengthException();
    }

    // Initialize expanded key with correct size.
    int expanded_key_size = (_ROUNDS + 1) * _Nk * 4;
    _expanded_key = Uint8List(expanded_key_size);

    // Copy initial key to expanded key.
    for (int i = 0; i < _Nk; ++i) {
      for (int j = 0; j < 4; ++j) {
        _expanded_key[4 * i + j] = initial_key[4 * i + j];
      }
    }

    // Temporary buffer that one word in size.
    var temp = Uint8List(4);

    // Go through all expantions. Each expantion lengthens the key
    // for one word. There are Nb words in each round key.
    for (int i = _Nk; i < _Nb * (_ROUNDS + 1); ++i) {
      // Copy the previous word into temp.
      for (int j = 0; j < 4; ++j) {
        temp[j] = _expanded_key[4 * (i - 1) + j];
      }

      if (i % _Nk == 0) {
        _rot_word(temp);
        _sub_word(temp);

        // XOR word with Rcon[i];
        temp[0] ^= rcon[i ~/ _Nk];
      }

      // word[i] = word[i - Nk] XOR temp
      for (int j = 0; j < 4; ++j) {
        _expanded_key[4 * i + j] = _expanded_key[4 * (i - _Nk) + j] ^ temp[j];
      }
    }
  }

  // Rotate word, that is circle shift one to the left.
  void _rot_word(Uint8List word) {
    int tmp = word[0];

    for (int i = 0; i < word.length - 1; ++i) {
      word[i] = word[i + 1];
    }

    word[word.length - 1] = tmp;
  }

  // Apply S-box to the word.
  void _sub_word(Uint8List word) {
    for (int i = 0; i < word.length; ++i) {
      word[i] = sbox[word[i]];
    }
  }

  // Converts class to string for easier printing.
  String toString() {
    return hex.encode(_expanded_key);
  }
}

main() {
  var kBytes =
      Uint8List.fromList(hex.decode('2b7e151628aed2a6abf7158809cf4f3c'));

  var k = Key(kBytes);
  print(k);
}
