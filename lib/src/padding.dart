import 'dart:typed_data';

/// Exception thrown when [Padding] input was not of correct length.
class PaddingInputLengthException implements Exception {
  @override
  String toString() => 'Input is of incorrect length.';
}

/// Abstract class representing a padding mode.
///
/// Padding is used to expand text to a multiple of block size,
/// so that it can be encrypted with [BlockCipherMode].
abstract class Padding {
  /// Adds padding to the input.
  ///
  /// Input is padded, so that it is a multiple of given block_size.
  Uint8List add_padding(Uint8List input, int block_size);

  /// Removes padding from input.
  Uint8List remove_padding(Uint8List input);
}

/// Implementation of PKCS#7 padding.
///
/// Number of each padded byte is the number of bytes that are added.
/// It is the most common padding.
class PKCS7 implements Padding {
  /// Adds padding to the input.
  ///
  /// Input is padded, so that it is a multiple of given block_size.
  /// Throws [PaddingInputLengthException] if input is not of correct length.
  @override
  Uint8List add_padding(Uint8List input, int block_size) {
    // Calculate number of blocks in padded text.
    int num_blocks = input.length ~/ block_size + 1;
    // Calculate number of bytes to be padded.
    int to_add = input.length - num_blocks * block_size;

    // Copy current data to expanded list.
    var res = Uint8List(num_blocks * block_size);
    for (int i = 0; i < input.length; ++i) {
      res[i] = input[i];
    }

    // Append bytes to list.
    for (int i = 0; i < to_add; ++i) {
      res[input.length + i] = to_add;
    }

    return res;
  }

  /// Removes padding from input.
  ///
  /// Throws [PaddingInputLengthException] if input is not of correct length.
  @override
  Uint8List remove_padding(Uint8List input) {
    // Checks that at least one element is in the list.
    if (input.length == 0) {
      throw PaddingInputLengthException();
    }

    // Get number of elements to be removed.
    int to_remove = input[input.length - 1];
    // Check that will not remove more elements than length of the list.
    if (to_remove > input.length) {
      throw PaddingInputLengthException();
    }

    // Remove elements and return new list.
    var res = Uint8List(input.length - to_remove);
    for (int i = 0; i < res.length; ++i) {
      res[i] = input[i];
    }

    return res;
  }
}
