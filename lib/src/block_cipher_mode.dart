import 'dart:typed_data';

import 'package:aes/aes.dart';

import 'aes.dart';

/// Exception thrown when [BlockCipherMode] input was not of correct length;
class BlockCipherModeInputLengthException implements Exception {
  final int _block_size;

  BlockCipherModeInputLengthException(this._block_size);

  @override
  String toString() {
    return 'Input is not multiple of cipher\'s block size ($_block_size).';
  }
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
