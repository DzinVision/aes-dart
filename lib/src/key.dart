import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'const.dart';

class KeyLengthException implements Exception {
  String toString() => 'Key is of invalid length.';
}

class KeyRoundException implements Exception {
  String toString() => 'Invalid round for round key requested.';
}

class Key {
  // Final expended key.
  Uint8List _expanded_key;

  Key(Uint8List initial_key) {
    _expand_key(initial_key);
  }

  // Expands the initial key to satisfy the length
  // needed for _rounds rounds.
  void _expand_key(Uint8List initial_key) {
    // Check that the size of the initial key is correct.
    if (initial_key.length != 4 * Nk) {
      throw KeyLengthException();
    }

    // Initialize expanded key with correct size.
    int expanded_key_size = (ROUNDS + 1) * Nk * 4;
    _expanded_key = Uint8List(expanded_key_size);

    // Copy initial key to expanded key.
    for (int i = 0; i < Nk; ++i) {
      for (int j = 0; j < 4; ++j) {
        _expanded_key[4 * i + j] = initial_key[4 * i + j];
      }
    }

    // Temporary buffer that one word in size.
    var temp = Uint8List(4);

    // Go through all expantions. Each expantion lengthens the key
    // for one word. There are Nb words in each round key.
    for (int i = Nk; i < Nb * (ROUNDS + 1); ++i) {
      // Copy the previous word into temp.
      for (int j = 0; j < 4; ++j) {
        temp[j] = _expanded_key[4 * (i - 1) + j];
      }

      if (i % Nk == 0) {
        _rot_word(temp);
        _sub_word(temp);

        // XOR word with Rcon[i];
        temp[0] ^= rcon[i ~/ Nk];
      }

      // word[i] = word[i - Nk] XOR temp
      for (int j = 0; j < 4; ++j) {
        _expanded_key[4 * i + j] = _expanded_key[4 * (i - Nk) + j] ^ temp[j];
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

  Uint8List round_key(int round) {
    if (round < 0 || round > ROUNDS) {
      throw KeyRoundException();
    }

    var key = Uint8List(Nb * 4);
    for (int i = 0; i < Nb * 4; ++i) {
      key[i] = _expanded_key[round * (Nb * 4) + i];
    }

    return key;
  }
}
