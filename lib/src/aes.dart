import 'dart:typed_data';

import 'const.dart';
import 'key.dart';

/// Exception returned when AES input was not of correct length.
class AESInputLengthException implements Exception {
  final int _required_length;
  final int _given_length;

  AESInputLengthException(this._given_length, this._required_length);

  String toString() =>
      'AES input of incorrect length. Got $_given_length bytes, require $_required_length bytes.';
}

/// Internal class representing AES state.
class _State {
  // A state is represented by 4x4 matrix.
  List<Uint8List> _state;

  // Initializes state with data. Data should be 16 bytes long.
  // The constructor does not check if data is of correct length,
  // since state is only constructed in AES class which checks the
  // data length.
  _State(Uint8List data) {
    // Create 4x4 state matrix.
    _state = List<Uint8List>(4);
    for (int i = 0; i < 4; ++i) {
      _state[i] = Uint8List(4);
    }

    // Copy data to state matrix.
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[j][i] = data[4 * i + j];
      }
    }
  }

  /// Adds (XORs) round key [round_key] to current state.
  void add_round_key(Uint8List round_key) {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[j][i] ^= round_key[4 * i + j];
      }
    }
  }

  /// Substitutes bytes in current state with help of sbox.
  void sub_bytes() {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[i][j] = sbox[_state[i][j]];
      }
    }
  }

  /// Shifts rows to the left as specified in AES standard.
  ///
  /// Row 0 is not shifted.
  /// Row 1 is shifted one to the left.
  /// Row 2 is shifted two to the left.
  /// Row 3 is shifted three to the left.
  void shift_rows() {
    for (int row = 0; row < 4; ++row) {
      // Shift the row indexOfRow-times.
      for (int j = 0; j < row; ++j) {
        int tmp = _state[row][0];

        for (int i = 0; i < 3; ++i) {
          _state[row][i] = _state[row][i + 1];
        }

        _state[row][3] = tmp;
      }
    }
  }

  /// Helper function that multiplies element p from GF(2^8) with
  /// element X from GF(2^8).
  int _xtime(int p) {
    return ((p << 1) & ((1 << 8) - 1)) ^ (((p >> 7) & 1) * 0x1b);
  }

  /// Multiplies elements p, q from GF(2^8).
  int _multiply(int p, int q) {
    int r = 0x00;
    int s = p;

    for (int i = 0; i < 8; ++i) {
      int b = q & 1;
      r = r ^ (b * s);

      q = q >> 1;
      s = _xtime(s);
    }

    return r;
  }

  /// Multiplies each column with a matrix specified in AES standard.
  void mix_columns() {
    for (int col = 0; col < 4; ++col) {
      int a = _state[0][col];
      int b = _state[1][col];
      int c = _state[2][col];
      int d = _state[3][col];

      _state[0][col] = _multiply(0x02, a) ^ _multiply(0x03, b) ^ c ^ d;
      _state[1][col] = a ^ _multiply(0x02, b) ^ _multiply(0x03, c) ^ d;
      _state[2][col] = a ^ b ^ _multiply(0x02, c) ^ _multiply(0x03, d);
      _state[3][col] = _multiply(0x03, a) ^ b ^ c ^ _multiply(0x02, d);
    }
  }

  /// Inverse of shift rows operation.
  ///
  /// Shifts rows to the right, to inverse the shift_rows operation.
  void inv_shift_rows() {
    for (int row = 0; row < 4; ++row) {
      // Shift row indexOfRow-times.
      for (int j = 0; j < row; ++j) {
        int tmp = _state[row][3];

        for (int i = 3; i > 0; --i) {
          _state[row][i] = _state[row][i - 1];
        }

        _state[row][0] = tmp;
      }
    }
  }

  /// Inverse of sub_bytes operation.
  ///
  /// Substitutes bytes with the help of rsbox which is the inverse of sbox.
  void inv_sub_bytes() {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[i][j] = rsbox[_state[i][j]];
      }
    }
  }

  /// Inverse of mix_columns operation.
  ///
  /// Multiplies each column with inverse matrix specified in AES standard.
  void inv_mix_columns() {
    for (int col = 0; col < 4; ++col) {
      int a = _state[0][col];
      int b = _state[1][col];
      int c = _state[2][col];
      int d = _state[3][col];

      _state[0][col] = _multiply(0x0e, a) ^
          _multiply(0x0b, b) ^
          _multiply(0x0d, c) ^
          _multiply(0x09, d);
      _state[1][col] = _multiply(0x09, a) ^
          _multiply(0x0e, b) ^
          _multiply(0x0b, c) ^
          _multiply(0x0d, d);
      _state[2][col] = _multiply(0x0d, a) ^
          _multiply(0x09, b) ^
          _multiply(0x0e, c) ^
          _multiply(0x0b, d);
      _state[3][col] = _multiply(0x0b, a) ^
          _multiply(0x0d, b) ^
          _multiply(0x09, c) ^
          _multiply(0x0e, d);
    }
  }

  /// Converts 4x4 state matrix to 16 bytes array.
  Uint8List to_out() {
    var out = Uint8List(4 * Nb);
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        out[4 * i + j] = _state[j][i];
      }
    }

    return out;
  }

  String toString() {
    var res = '';
    for (int i = 0; i < 4; ++i) {
      var row = '';
      for (int j = 0; j < 4; ++j) {
        row += _state[i][j].toRadixString(16) + ' ';
      }

      res += row;
      if (i < 3) {
        res += '\n';
      }
    }

    return res;
  }
}

/// Abstract class representing a block cipher.
/// Constructor of block cipher should take key as parameter.
abstract class BlockCipher {
  /// Encrypts a single block of [input] plain text and returns ciphered data.
  ///
  /// [input] must be the same length as block size of the cipher.
  Uint8List encrypt(Uint8List input);

  /// Decrypts a single block [input] cipher text and returns plain text data.
  ///
  /// Input must be the same length as block size of the cipher.
  Uint8List decrypt(Uint8List input);

  /// Returns cipher's block size in bytes.
  int get block_size;
}

/// Implementation of AES 128 block cipher.
///
/// Object is constructed with a 16 byte long key used for encryption and
/// decryption. After initializing the object with a key, you can call
/// its encrypt and decrypt methods to encrypt or decrypt a single
/// 16 byte long block of data. AES should be used with [CBC] (or [ECB])
/// block cipher mode to encrypt or decrypt multiple blocks of data.
///
/// The following example shows how AES is used to encrypt and decrypt
/// a single block of data. The example uses a key of zeros. Encrypted block
/// is also block of zeros.
/// ```dart
/// // Initialize key and aes object.
/// var key = Key(Uint8List(16));
/// var aes = AES(key);
///
/// // Encrypt data and decrypt encrypted data.
/// var data = Uint8List(16);
/// var encrypted = aes.encrypt(data);
/// var decrypted = aes.decrypt(encrypted);
/// ```
class AES implements BlockCipher {
  final Key _key;

  /// Constructor takes key that is used for encryption and decryption.
  AES(this._key);

  @override
  int get block_size {
    // A single AES block contains 4 words, each word is 4 bytes.
    return 4 * Nb;
  }

  /// Encrypts [input] plain text using AES 128 and returns ciphered data.
  ///
  /// [input] must be 16 bytes long, since that is AES block size.
  /// Returned list is 16 bytes long.
  /// Throws [AESInputLengthException] if [input] is not of correct length.
  @override
  Uint8List encrypt(Uint8List input) {
    // Check that the input is of correct size.
    if (input.length != 4 * Nb) {
      throw AESInputLengthException(input.length, 4 * Nb);
    }

    // Initialize state and add round key.
    var state = _State(input);
    state.add_round_key(_key.round_key(0));

    // Execute ROUNDS - 1 normal rounds.
    for (int round = 1; round < ROUNDS; ++round) {
      state.sub_bytes();
      state.shift_rows();
      state.mix_columns();
      state.add_round_key(_key.round_key(round));
    }

    // Execute last round, which is different than the first ROUNDS - 1.
    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(_key.round_key(ROUNDS));

    // Return bytes output.
    return state.to_out();
  }

  /// Decrypts [input] cipher text using AES128 and returns plain text data.
  ///
  /// [input] must be 16 bytes long, since that is AES block size.
  /// Returned list is 16 bytes long.
  /// Throws [AESInputLengthException] if [input] is not of correct length.
  @override
  Uint8List decrypt(Uint8List input) {
    // Check that the input is of correct size.
    if (input.length != 4 * Nb) {
      throw AESInputLengthException(input.length, 4 * Nb);
    }

    // Initialize state and add round key.
    var state = _State(input);
    state.add_round_key(_key.round_key(ROUNDS));

    // Execute ROUNDS - 1 normal decryption rounds.
    for (int round = ROUNDS - 1; round > 0; --round) {
      state.inv_shift_rows();
      state.inv_sub_bytes();
      state.add_round_key(_key.round_key(round));
      state.inv_mix_columns();
    }

    // Execute last round, which is different that the first ROUNDS - 1.
    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(_key.round_key(0));

    // Return bytes output.
    return state.to_out();
  }
}
