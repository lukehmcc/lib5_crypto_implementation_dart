// ! This implementation is copied from https://github.com/mnito/thirds (see below BSD-3 license)
// ! with some minor modifications

/*
Copyright 2022, Michael P. Nitowski <mike@nitow.ski>. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

import 'dart:math';
import 'dart:typed_data';

// BLAKE3 Implementation
// Based on public domain software at
// https://github.com/BLAKE3-team/BLAKE3
// and
// https://github.com/oconnor663/bao
// Translator: Michael P. Nitowski

final _OUT_LENGTH = 32;
final _BLOCK_LENGTH = 64;
final _BLOCK_WORD_LENGTH = _BLOCK_LENGTH ~/ 4;

final _CHUNK_LENGTH = 1024;

final _FLAG_CHUNK_START = 1 << 0;
final _FLAG_CHUNK_END = 1 << 1;
final _FLAG_PARENT = 1 << 2;
final _FLAG_ROOT = 1 << 3;

final _MAX_WORD_SIZE = 0xffffffff;

final _IV = Uint32List.fromList([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

int _ROTR32(int x, int y) => (((x) >> (y)) ^ ((x) << (32 - (y))));

int _load32(Uint8List b) => b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24);

Uint8List _store32(int n) {
  final bytes = Uint8List(4);

  bytes[0] = n & 0xff;
  bytes[1] = (n >> 8) & 0xff;
  bytes[2] = (n >> 16) & 0xff;
  bytes[3] = (n >> 24) & 0xff;

  return bytes;
}

Uint32List _blockBytesToWords(Uint8List b) {
  final words = Uint32List(_BLOCK_WORD_LENGTH);

  words[0] = _load32(Uint8List.view(b.buffer, 0, 4));
  words[1] = _load32(Uint8List.view(b.buffer, 4, 4));
  words[2] = _load32(Uint8List.view(b.buffer, 8, 4));
  words[3] = _load32(Uint8List.view(b.buffer, 12, 4));
  words[4] = _load32(Uint8List.view(b.buffer, 16, 4));
  words[5] = _load32(Uint8List.view(b.buffer, 20, 4));
  words[6] = _load32(Uint8List.view(b.buffer, 24, 4));
  words[7] = _load32(Uint8List.view(b.buffer, 28, 4));
  words[8] = _load32(Uint8List.view(b.buffer, 32, 4));
  words[9] = _load32(Uint8List.view(b.buffer, 36, 4));
  words[10] = _load32(Uint8List.view(b.buffer, 40, 4));
  words[11] = _load32(Uint8List.view(b.buffer, 44, 4));
  words[12] = _load32(Uint8List.view(b.buffer, 48, 4));
  words[13] = _load32(Uint8List.view(b.buffer, 52, 4));
  words[14] = _load32(Uint8List.view(b.buffer, 56, 4));
  words[15] = _load32(Uint8List.view(b.buffer, 60, 4));

  return words;
}

void _G(Uint32List v, int a, int b, int c, int d, int x, int y) {
  v[a] = (((v[a] + v[b]) & _MAX_WORD_SIZE) + x) & _MAX_WORD_SIZE;
  v[d] = _ROTR32(v[d] ^ v[a], 16);
  v[c] = (v[c] + v[d]) & _MAX_WORD_SIZE;
  v[b] = _ROTR32(v[b] ^ v[c], 12);
  v[a] = (((v[a] + v[b]) & _MAX_WORD_SIZE) + y) & _MAX_WORD_SIZE;
  v[d] = _ROTR32(v[d] ^ v[a], 8);
  v[c] = (v[c] + v[d]) & _MAX_WORD_SIZE;
  v[b] = _ROTR32(v[b] ^ v[c], 7);
}

final _SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
  [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
  [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
  [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
  [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
  [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

void _round(Uint32List state, Uint32List msg, int round) {
  _G(state, 0, 4,  8, 12, msg[_SIGMA[round][0]], msg[_SIGMA[round][1]]);
  _G(state, 1, 5,  9, 13, msg[_SIGMA[round][2]], msg[_SIGMA[round][3]]);
  _G(state, 2, 6, 10, 14, msg[_SIGMA[round][4]], msg[_SIGMA[round][5]]);
  _G(state, 3, 7, 11, 15, msg[_SIGMA[round][6]], msg[_SIGMA[round][7]]);
  _G(state, 0, 5, 10, 15, msg[_SIGMA[round][8]], msg[_SIGMA[round][9]]);
  _G(state, 1, 6, 11, 12, msg[_SIGMA[round][10]], msg[_SIGMA[round][11]]);
  _G(state, 2, 7,  8, 13, msg[_SIGMA[round][12]], msg[_SIGMA[round][13]]);
  _G(state, 3, 4,  9, 14, msg[_SIGMA[round][14]], msg[_SIGMA[round][15]]);
}

Uint32List _compressFirst8(
  Uint32List cv,
  Uint32List blockWords,
  int counter,
  int blockLength,
  int flags
) {
  final state = Uint32List(16);

  state[0] = cv[0];
  state[1] = cv[1];
  state[2] = cv[2];
  state[3] = cv[3];
  state[4] = cv[4];
  state[5] = cv[5];
  state[6] = cv[6];
  state[7] = cv[7];
  state[8] = _IV[0];
  state[9] = _IV[1];
  state[10] = _IV[2];
  state[11] = _IV[3];
  state[12] = counter & 0xffffffff;
  state[13] = counter >> 32;
  state[14] = blockLength;
  state[15] = flags;

  _round(state, blockWords, 0);
  _round(state, blockWords, 1);
  _round(state, blockWords, 2);
  _round(state, blockWords, 3);
  _round(state, blockWords, 4);
  _round(state, blockWords, 5);
  _round(state, blockWords, 6);

  state[0] = state[0] ^ state[8];
  state[1] = state[1] ^ state[9];
  state[2] = state[2] ^ state[10];
  state[3] = state[3] ^ state[11];
  state[4] = state[4] ^ state[12];
  state[5] = state[5] ^ state[13];
  state[6] = state[6] ^ state[14];
  state[7] = state[7] ^ state[15];

  return state;
}

Uint32List _compress(
  Uint32List cv,
  Uint32List blockWords,
  int counter,
  int blockLength,
  int flags
) {
  final state = _compressFirst8(cv, blockWords, counter, blockLength, flags);

  state[8] = state[8] ^ cv[0];
  state[9] = state[9] ^ cv[1];
  state[10] = state[10] ^ cv[2];
  state[11] = state[11] ^ cv[3];
  state[12] = state[12] ^ cv[4];
  state[13] = state[13] ^ cv[5];
  state[14] = state[14] ^ cv[6];
  state[15] = state[15] ^ cv[7];

  return state;
}

class _Output {
  Uint32List inputCv;
  Uint32List blockWords;
  int counter;
  int blockLength;
  int flags;

  _Output(
    this.inputCv,
    this.blockWords,
    this.counter,
    this.blockLength,
    this.flags
  );
}

Uint32List _getChainingValue(_Output o) {
  final compressed = _compressFirst8(
    o.inputCv,
    o.blockWords,
    o.counter,
    o.blockLength,
    o.flags
  );

  return Uint32List.view(compressed.buffer, 0, 8);
}

class _ChunkState {
  Uint32List cv;
  int chunkCounter;
  Uint8List block = Uint8List(_BLOCK_LENGTH);
  int blockLength = 0;
  int blocksCompressed = 0;
  int flags;

  _ChunkState(
    this.cv,
    this.chunkCounter,
    this.flags
  );
}

int _chunkLength(_ChunkState chunk) {
  return _BLOCK_LENGTH * chunk.blocksCompressed + chunk.blockLength;
}

void _chunkUpdate(_ChunkState chunk, Uint8List input) {
  final blockData = chunk.block.buffer.asByteData();

  int taken = 0;
  while (taken < input.length) {
    if (chunk.blockLength == _BLOCK_LENGTH) {
      final blockWords = _blockBytesToWords(chunk.block);

      chunk.cv = Uint32List.view(
        _compressFirst8(
          chunk.cv,
          blockWords,
          chunk.chunkCounter,
          _BLOCK_LENGTH,
          chunk.flags | (chunk.blocksCompressed == 0 ? _FLAG_CHUNK_START : 0),
        ).buffer, 0, 8
      );

      chunk.blocksCompressed++;
      // Clear block
      for (int i = 0; i < _BLOCK_LENGTH; i += 4) {
        blockData.setUint32(i, 0);
      }
      chunk.blockLength = 0;
    }

    final take = min(_BLOCK_LENGTH - chunk.blockLength, input.length - taken);
    for (int i = 0; i < take; i++) {
      blockData.setUint8(chunk.blockLength + i, input[taken + i]);
    }
    chunk.blockLength += take;
    taken += take;
  }
}

_Output _chunkOutput(_ChunkState chunk) {
  final blockWords = _blockBytesToWords(chunk.block);
  return _Output(
    chunk.cv,
    blockWords,
    chunk.chunkCounter,
    chunk.blockLength,
    (
      chunk.flags
      | (chunk.blocksCompressed == 0 ? _FLAG_CHUNK_START : 0)
      | _FLAG_CHUNK_END
    )
  );
}

_Output _parentOutput(
  Uint32List leftChildCv,
  Uint32List rightChildCv,
  Uint32List key,
  int flags,
) {
  final blockWords = Uint32List(16);
  blockWords.setAll(0, leftChildCv);
  blockWords.setAll(8, rightChildCv);

  return _Output(key, blockWords, 0, _BLOCK_LENGTH, _FLAG_PARENT | flags);
}

Uint32List _parentCv(
  Uint32List leftChildCv,
  Uint32List rightChildCv,
  Uint32List key,
  int flags,
) {
  return _getChainingValue(
    _parentOutput(leftChildCv, rightChildCv, key, flags)
  );
}

class HashContext {
  _ChunkState chunk;
  Uint32List _key;
  final List<Uint32List?> _cVStack = List<Uint32List?>.filled(54, null);
  int _cvStackLength = 0;
  int _flags;

  HashContext._(key, flags) : _key = Uint32List.fromList(key), chunk = _ChunkState(key, 0, flags), _flags = flags;

  HashContext(): this._(_IV, 0);

  void reset() {
    chunk = _ChunkState(_key, 0, _flags);
    _cVStack.fillRange(0, 54, null);
    _cvStackLength = 0;
  }

  void _pushCv(Uint32List cv) {
    _cVStack[_cvStackLength++] = cv;
  }

  Uint32List _popCv() {
    return _cVStack[--_cvStackLength]!;
  }

  _addChunkCv(Uint32List newCv, int totalChunks) {
    while(totalChunks & 1 == 0) {
      newCv = _parentCv(_popCv(), newCv, _key, _flags);
      totalChunks >>= 1;
    }
    _pushCv(newCv);
  }

  update(Uint8List input) {
    var taken = 0;

    while (taken < input.length) {
      if (_chunkLength(chunk) == _CHUNK_LENGTH) {
        final chunkCv = _getChainingValue(_chunkOutput(chunk));
        final totalChunks = chunk.chunkCounter + 1;
        _addChunkCv(chunkCv, totalChunks);
        chunk = _ChunkState(_key, totalChunks, _flags);
      }

      final take = min(_CHUNK_LENGTH - _chunkLength(chunk), input.length);
      _chunkUpdate(
        chunk,
        Uint8List.view(input.buffer, taken, min(take, input.length - taken))
      );
      taken += take;
    }
  }

  finalize(Uint8List output) {
    final outputData = output.buffer.asByteData();

    _Output o = _chunkOutput(chunk);
    int parentNodesRemaining = _cvStackLength;
    while (parentNodesRemaining > 0) {
      parentNodesRemaining--;
      o = _parentOutput(
        _cVStack[parentNodesRemaining]!,
        _getChainingValue(o),
        _key,
        _flags
      );
    }

    int outputBlockCounter = 0;
    for (int i = 0; i < output.length; i += 2 * _OUT_LENGTH) {
      final words = _compress(
        o.inputCv,
        o.blockWords,
        outputBlockCounter,
        o.blockLength,
        o.flags | _FLAG_ROOT
      );

      int j = 0;
      for (final word in words) {
        final bytes = _store32(word);

        if (i + j + 4 <= output.length) {
          outputData.setUint8(i + j, bytes[0]);
          outputData.setUint8(i + j + 1, bytes[1]);
          outputData.setUint8(i + j + 2, bytes[2]);
          outputData.setUint8(i + j + 3, bytes[3]);
        } else {
          for (int n = 0; n < output.length - (i + j); n++) {
            outputData.setUint8(i + j + n, bytes[n]);
          }
        }

        j += 4;

        if (j >= output.length) {
          break;
        }
      }
    }

    return output;
  }
}
