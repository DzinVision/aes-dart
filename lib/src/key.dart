import 'dart:typed_data';

import 'package:convert/convert.dart';

import 'const.dart';

/// Initial key given to expansion algorithm is not of correct size.
class KeyLengthException implements Exception {
  final int _required_length;
  final int _given_length;

  KeyLengthException(this._given_length, this._required_length);

  String toString() =>
      'Key is of invalid length. Got $_given_length bytes, require $_required_length bytes.';
}

/// Requested round key does not exist.
class KeyRoundException implements Exception {
  final int _requested_round;

  KeyRoundException(this._requested_round);

  String toString() => 'Round key for $_requested_round does not exist.';
}

/// Object that handles round keys for AES 128.
///
/// Key object is constructed form single 128 bit key
/// on which key expansion is performed to generate a key schedule use by AES 128.
///
/// Example of creating an AES key from list of zeros.
/// ```dart
/// var key = Key(Uint8List(16));
/// ```
class Key {
  // Final expended key.
  Uint8List _expanded_key;

  /// Constructs key with specified [initial_key] key.
  ///
  /// [initial_key] must 16 bytes long, otherwise [KeyLengthException] is thrown.
  Key(Uint8List initial_key) {
    _expand_key(initial_key);
  }

  /// Performs a key expansion routine to generate a key schedule.
  ///
  /// Throws a [KeyLengthException] if length of the [initial_key] is incorrect.
  void _expand_key(Uint8List initial_key) {
    // Check that the size of the initial key is correct.
    if (initial_key.length != 4 * Nk) {
      throw KeyLengthException(initial_key.length, 4 * Nk);
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

    // Temporary buffer that holds the last word in key.
    var temp = Uint8List(4);

    // Perform expansion routine. Key schedule has ROUND + 1
    // round keys, each round key is Nb word long.
    for (int i = Nk; i < Nb * (ROUNDS + 1); ++i) {
      // Copy the previous word into temp.
      for (int j = 0; j < 4; ++j) {
        temp[j] = _expanded_key[4 * (i - 1) + j];
      }

      if (i % Nk == 0) {
        // Execute temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]

        _rot_word(temp);
        _sub_word(temp);

        temp[0] ^= rcon[i ~/ Nk];
      }

      // word[i] = word[i - Nk] XOR temp
      for (int j = 0; j < 4; ++j) {
        _expanded_key[4 * i + j] = _expanded_key[4 * (i - Nk) + j] ^ temp[j];
      }
    }
  }

  /// Rotate word [word], that is circle shift one to the left.
  void _rot_word(Uint8List word) {
    int tmp = word[0];

    for (int i = 0; i < word.length - 1; ++i) {
      word[i] = word[i + 1];
    }

    word[word.length - 1] = tmp;
  }

  /// Apply S-box to the word [word].
  void _sub_word(Uint8List word) {
    for (int i = 0; i < word.length; ++i) {
      word[i] = sbox[word[i]];
    }
  }

  String toString() {
    return hex.encode(_expanded_key);
  }

  /// Returns round key for specified [round].
  ///
  /// Throws a [KeyRoundException] if requested [round] is not valid.
  ///
  /// Round key is 4 words (16 bytes) long key, that starts at
  /// word `round * Nb` and ends at word `(round + 1) * Nb`. Since expanded
  /// key is stored as array of bytes, round key starts at byte `round * Nb * 4`
  /// and ends at byte `(round + 1) * Nb * 4`.
  Uint8List round_key(int round) {
    // Check that the specified round is valid.
    if (round < 0 || round > ROUNDS) {
      throw KeyRoundException(round);
    }

    // Initialize array representing round key of size 16 bytes.
    var key = Uint8List(Nb * 4);

    // Copy correct round key to key array.
    for (int i = 0; i < Nb * 4; ++i) {
      key[i] = _expanded_key[round * (Nb * 4) + i];
    }

    return key;
  }
}
