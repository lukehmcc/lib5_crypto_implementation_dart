import 'dart:math';
import 'dart:typed_data';

import 'package:lib5/lib5.dart';
import 'package:thirds/blake3.dart';
import 'package:cryptography/cryptography.dart';

class DartCryptoImplementation extends CryptoImplementation {
  final xchacha20 = Xchacha20.poly1305Aead();

  @override
  Future<Uint8List> decryptXChaCha20Poly1305(
      {required Uint8List key,
      required Uint8List nonce,
      required Uint8List ciphertext}) async {
    final macIndex = ciphertext.length - 16;
    final res = await xchacha20.decrypt(
      SecretBox(
        ciphertext.sublist(0, macIndex),
        nonce: nonce,
        mac: Mac(ciphertext.sublist(macIndex)),
      ),
      secretKey: SecretKey(key),
    );
    return Uint8List.fromList(res);
  }

  @override
  Future<Uint8List> encryptXChaCha20Poly1305(
      {required Uint8List key,
      required Uint8List nonce,
      required Uint8List plaintext}) async {
    final res = await xchacha20.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: nonce,
    );
    return Uint8List.fromList(res.cipherText + res.mac.bytes);
  }

  final ed25519 = Ed25519();
  final _defaultSecureRandom = Random.secure();

  @override
  Uint8List generateRandomBytes(int length) {
    final bytes = Uint8List(length);

    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = _defaultSecureRandom.nextInt(256);
    }

    return bytes;
  }

  @override
  Future<Uint8List> hashBlake3(Uint8List input) async {
    return Uint8List.fromList(blake3(input));
  }

  @override
  Uint8List hashBlake3Sync(Uint8List input) {
    return Uint8List.fromList(blake3(input));
  }

  @override
  Future<KeyPairEd25519> newKeyPairEd25519({required Uint8List seed}) async {
    final keyPair = await ed25519.newKeyPairFromSeed(seed);
    final pk = (await keyPair.extractPublicKey()).bytes;
    return KeyPairEd25519(Uint8List.fromList(seed + pk));
  }

  @override
  Future<Uint8List> signEd25519({
    required KeyPairEd25519 kp,
    required Uint8List message,
  }) async {
    final signature = await ed25519.sign(
      message,
      keyPair: SimpleKeyPairData(kp.extractBytes().sublist(0, 32),
          publicKey: SimplePublicKey(
            kp.extractBytes().sublist(32),
            type: KeyPairType.ed25519,
          ),
          type: KeyPairType.ed25519),
    );
    return Uint8List.fromList(signature.bytes);
  }

  @override
  Future<bool> verifyEd25519({
    required Uint8List pk,
    required Uint8List message,
    required Uint8List signature,
  }) async {
    return ed25519.verify(
      message,
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(
          pk,
          type: KeyPairType.ed25519,
        ),
      ),
    );
  }
}
