import 'dart:typed_data';

import 'package:aes/aes.dart';

import 'aes.dart';
import 'package:convert/convert.dart';

/// Exception thrown when [BlockCipherMode] input was not of correct length;
class BlockCipherModeInputLengthException implements Exception {
  final int _block_size;

  BlockCipherModeInputLengthException(this._block_size);

  @override
  String toString() {
    return 'Input is not multiple of cipher\'s block size ($_block_size).';
  }
}

/// Exception thrown when IV given to [BlockCipherMode] was not of correct length;
class BlockCipherModeIVLengthException implements Exception {
  final int _required_length;
  final int _given_length;

  BlockCipherModeIVLengthException(this._given_length, this._required_length);

  @override
  String toString() =>
      'IV has incorrect length. Got $_given_length bytes, require $_required_length bytes.';
}

/// Abstract class representing a block cipher mode (for instance ECB or CBC).
abstract class BlockCipherMode {
  /// Encrypts multiple blocks of plain text data in [input] and returns ciphered data.
  ///
  /// [input] length must be a multiple of cipher's block size.
  Uint8List encrypt(Uint8List input);

  /// Decrypts multiple blocks of cipher data in [input] and returns plain text data.
  ///
  /// [input] length must be a multiple of cipher's block size.
  Uint8List decrypt(Uint8List input);
}

/// Implementation of ECB block cipher mode.
///
/// ECB block mode is the least secure of all and should not be used.
/// It encrypts each block individually.
///
/// The following example uses ECB with AES to encrypt 64 bytes long
/// list of zeros with key of zeros.
/// ```dart
/// // Initialize key, aes and ecb objects.
/// var key = Key(Uint8List(16));
/// var aes = AES(key);
/// var ecb = ECB(aes);
///
/// // Encrypt data and decrypt encrypted data.
/// var data = Uint8List(64);
/// var encrypted = ecb.encrypt(data);
/// var decrypted = ecb.decrypt(encrypted);
/// ```
class ECB implements BlockCipherMode {
  final BlockCipher _cipher;

  /// Constructs ECB block mode with specified [BlockCipher].
  ECB(this._cipher);

  /// Encrypts [input] using provided [_cipher] and returns ciphered data.
  ///
  /// [input] must be a multiple of [_cipher.block_size] long.
  /// Returned list is the same length as the input.
  /// Throws [BlockCipherModeInputLengthException] if [input] is not of correct length.
  @override
  Uint8List encrypt(Uint8List input) {
    // Check that the input is of correct length.
    if (input.length % _cipher.block_size != 0) {
      throw BlockCipherModeInputLengthException(_cipher.block_size);
    }

    // Calculate number of blocks in input.
    int num_of_blocks = input.length ~/ _cipher.block_size;

    // Initialize output list.
    var out = Uint8List(input.length);

    // Encrypt each block.
    for (int block = 0; block < num_of_blocks; ++block) {
      // Encrypt block.
      var encrypted = _cipher.encrypt(input.sublist(
          block * _cipher.block_size, (block + 1) * _cipher.block_size));

      // Copy block to output list.
      for (int i = 0; i < _cipher.block_size; ++i) {
        out[block * _cipher.block_size + i] = encrypted[i];
      }
    }

    return out;
  }

  /// Decrypts [input] using provided [_cipher] and returns plain text data.
  ///
  /// [input] must be a multiple of [_cipher.block_size] long.
  /// Returned list is the same length as the input.
  /// Throws [BlockCipherModeInputLengthException] if [input] is not of correct length.
  @override
  Uint8List decrypt(Uint8List input) {
    // Check that the input is of correct length.
    if (input.length % _cipher.block_size != 0) {
      throw BlockCipherModeInputLengthException(_cipher.block_size);
    }

    // Calculate number of blocks in input.
    int num_of_blocks = input.length ~/ _cipher.block_size;

    // Initialize output list.
    var out = Uint8List(input.length);

    // Decrypt each block.
    for (int block = 0; block < num_of_blocks; ++block) {
      // Decrypt block.
      var decrypted = _cipher.decrypt(input.sublist(
          block * _cipher.block_size, (block + 1) * _cipher.block_size));

      // Copy block to output list.
      for (int i = 0; i < _cipher.block_size; ++i) {
        out[block * _cipher.block_size + i] = decrypted[i];
      }
    }

    return out;
  }
}

/// Implementation of CBC block cipher mode.
///
/// CBC is more secure than ECB, therefore CBC should be used.
///
/// The following example uses CBC with AES to encrypt 64 bytes long
/// list of zeros with key of zeros.
/// ```dart
/// // Initialize key, aes and cbc objects.
/// var key = Key(Uint8List(16));
/// var aes = AES(key);
/// var cbc = CBC(aes);
///
/// // Encrypt data and decrypt encrypted data.
/// var data = Uint8List(64);
/// var encrypted = cbc.encrypt(data);
/// var decrypted = cbc.decrypt(encrypted);
/// ```
class CBC implements BlockCipherMode {
  final BlockCipher _cipher;
  final Uint8List _IV;

  /// Constructs ECB block mode with specified [BlockCipher] and IV.
  ///
  /// IV should be the size of cipher's block size.
  /// Throws [BlockCipherModeIVLengthException] if IV is not of correct length;
  CBC(this._cipher, this._IV) {
    // Check that the IV is of correct size.
    if (_IV.length != _cipher.block_size) {
      throw BlockCipherModeIVLengthException(_IV.length, _cipher.block_size);
    }
  }

  /// Encrypts [input] using provided [_cipher] and returns ciphered data.
  ///
  /// [input] must be a multiple of [_cipher.block_size] long.
  /// Returned list is the same length as the input.
  /// Throws [BlockCipherModeInputLengthException] if [input] is not of correct length.
  @override
  Uint8List encrypt(Uint8List input) {
    // Check that the input is of correct length.
    if (input.length % _cipher.block_size != 0) {
      throw BlockCipherModeInputLengthException(_cipher.block_size);
    }

    // Calculate number of blocks in input.
    int num_of_blocks = input.length ~/ _cipher.block_size;

    // Initialize output list.
    var out = Uint8List(input.length);

    // Remember previous ciphered block, to use with XOR.
    // For the first block IV is used.
    Uint8List prev_c = _IV;

    // Encrypt each block.
    for (int block = 0; block < num_of_blocks; ++block) {
      // Get a single block of data.
      var data = input.sublist(
          block * _cipher.block_size, (block + 1) * _cipher.block_size);

      // XOR data with previous ciphered block.
      for (int i = 0; i < _cipher.block_size; ++i) {
        data[i] ^= prev_c[i];
      }

      // Encrypt XOR-ed data and store it in prev_c, so that
      // it can be used for XOR-ing the next block.
      prev_c = _cipher.encrypt(data);

      // Copy encrypted bytes to out.
      for (int i = 0; i < _cipher.block_size; ++i) {
        out[block * _cipher.block_size + i] = prev_c[i];
      }
    }

    return out;
  }

  /// Decrypts [input] using provided [_cipher] and returns plain text data.
  ///
  /// [input] must be a multiple of [_cipher.block_size] long.
  /// Returned list is the same length as the input.
  /// Throws [BlockCipherModeInputLengthException] if [input] is not of correct length.
  @override
  Uint8List decrypt(Uint8List input) {
    // Check that the input is of correct length.
    if (input.length % _cipher.block_size != 0) {
      throw BlockCipherModeInputLengthException(_cipher.block_size);
    }

    // Calculate number of blocks in input.
    int num_of_blocks = input.length ~/ _cipher.block_size;

    // Initialize output list.
    var out = Uint8List(input.length);

    // Remember previous ciphered block, to use with XOR.
    // For the first block IV is used.
    Uint8List prev_c = _IV;

    // Decrypt each block.
    for (int block = 0; block < num_of_blocks; ++block) {
      // Get a single block of data.
      var data = input.sublist(
          block * _cipher.block_size, (block + 1) * _cipher.block_size);

      // Decrypt the block.
      var decrypted = _cipher.decrypt(data);

      // XOR decrypted block with previous ciphered block and
      // save result to out.
      for (int i = 0; i < _cipher.block_size; ++i) {
        out[block * _cipher.block_size + i] = decrypted[i] ^ prev_c[i];
      }

      // Remember previous ciphered block.
      prev_c = data;
    }

    return out;
  }
}
