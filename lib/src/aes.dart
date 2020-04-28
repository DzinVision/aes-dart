import 'dart:typed_data';

import 'const.dart';
import 'key.dart';

class AESInputLengthException implements Exception {
  String toString() => 'AES input of incorrect length.';
}

class _State {
  List<Uint8List> _state;

  _State(Uint8List data) {
    _state = List<Uint8List>(4);
    for (int i = 0; i < 4; ++i) {
      _state[i] = Uint8List(4);
    }

    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[j][i] = data[4 * i + j];
      }
    }
  }

  void add_round_key(Uint8List round_key) {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[j][i] ^= round_key[4 * i + j];
      }
    }
  }

  void sub_bytes() {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[i][j] = sbox[_state[i][j]];
      }
    }
  }

  void shift_rows() {
    for (int row = 0; row < 4; ++row) {
      for (int j = 0; j < row; ++j) {
        int tmp = _state[row][0];

        for (int i = 0; i < 3; ++i) {
          _state[row][i] = _state[row][i + 1];
        }

        _state[row][3] = tmp;
      }
    }
  }

  int _xtime(int p) {
    return ((p << 1) & ((1 << 8) - 1)) ^ (((p >> 7) & 1) * 0x1b);
  }

  int _multiply(int p, int q) {
    int r = 0x00;
    int s = p;

    while (q > 0) {
      int b = q & 1;
      r = r ^ (b * s);

      q = q >> 1;
      s = _xtime(s);
    }

    return r;
  }

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

  void inv_shift_rows() {
    for (int row = 0; row < 4; ++row) {
      for (int j = 0; j < row; ++j) {
        int tmp = _state[row][3];

        for (int i = 3; i > 0; --i) {
          _state[row][i] = _state[row][i - 1];
        }

        _state[row][0] = tmp;
      }
    }
  }

  void inv_sub_bytes() {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        _state[i][j] = rsbox[_state[i][j]];
      }
    }
  }

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

class AES {
  final Key _key;

  AES(this._key);

  Uint8List encrypt(Uint8List input) {
    if (input.length != 4 * Nb) {
      throw AESInputLengthException();
    }

    var state = _State(input);
    state.add_round_key(_key.round_key(0));

    for (int round = 1; round < ROUNDS; ++round) {
      state.sub_bytes();
      state.shift_rows();
      state.mix_columns();
      state.add_round_key(_key.round_key(round));
    }

    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(_key.round_key(ROUNDS));

    return state.to_out();
  }

  Uint8List decrypt(Uint8List input) {
    if (input.length != 4 * Nb) {
      throw AESInputLengthException();
    }

    var state = _State(input);
    state.add_round_key(_key.round_key(ROUNDS));

    for (int round = ROUNDS - 1; round > 0; --round) {
      state.inv_shift_rows();
      state.inv_sub_bytes();
      state.add_round_key(_key.round_key(round));
      state.inv_mix_columns();
    }

    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(_key.round_key(0));

    return state.to_out();
  }
}
