import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:dart_nats/src/common.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// Version byte for encoded NATS Seeds (base32-encodes to 'S...')
const PrefixByteSeed = 18 << 3;

/// Version byte for encoded NATS Private keys (base32-encodes to 'P...')
const PrefixBytePrivate = 15 << 3;

/// Version byte for encoded NATS Servers (base32-encodes to 'N...')
const PrefixByteServer = 13 << 3;

/// Version byte for encoded NATS Clusters (base32-encodes to 'C...')
const PrefixByteCluster = 2 << 3;

/// Version byte for encoded NATS Operators (base32-encodes to 'O...')
const PrefixByteOperator = 14 << 3;

/// Version byte for encoded NATS Accounts (base32-encodes to 'A...')
const PrefixByteAccount = 0;

/// Version byte for encoded NATS Users (base32-encodes to 'U...')
const PrefixByteUser = 20 << 3;

/// Version byte for unknown prefixes (base32-encodes to 'X...')
const PrefixByteUnknown = 23 << 3;

/// A class for managing NATS key pairs and cryptographic operations.
///
/// Nkeys provides functionality for:
/// - Generating new key pairs
/// - Loading keys from seeds
/// - Signing data
/// - Verifying signatures
/// - Converting between different key formats
///
/// The class implements the NATS NKeys protocol which uses Ed25519 keys with
/// special prefixes to identify different key types (user, account, server etc).
///
/// Example:
/// ```dart
/// // Generate new user keys
/// final userKeys = Nkeys.newNkeys(PrefixByteUser);
///
/// // Create from seed
/// final keys = Nkeys.fromSeed('SUAML5QBZM6VOOW4YPXKW3YZXVVJNFVVKWB4J4KVKTZAHZD37PNGLG5TTE');
///
/// // Sign data
/// final signature = keys.sign('Hello');
/// ```
///
/// See also:
/// * [PrefixByteUser] - Prefix for user keys
/// * [PrefixByteAccount] - Prefix for account keys
/// * [PrefixByteServer] - Prefix for server keys
/// * [fromSeed] - Creates keys from a seed string
/// * [newNkeys] - Generates new random keys
class Nkeys {
  /// The Ed25519 key pair used for signing and verification
  ed.KeyPair keyPair;

  /// Gets the raw seed bytes from the Ed25519 private key.
  ///
  /// The raw seed is the 32-byte private key seed used by Ed25519. This is different
  /// from the encoded seed string used by NATS which includes prefix bytes.
  ///
  /// Returns:
  /// A [Uint8List] containing the 32-byte raw seed value.
  ///
  /// See also:
  /// * [fromSeed] - Creates Nkeys from an encoded seed string
  /// * [ed.seed] - Gets raw seed from Ed25519 private key
  Uint8List get rawSeed {
    return ed.seed(keyPair.privateKey);
  }

  /// The prefix byte that identifies the key type (user, account, server etc).
  int prefixByte;

  /// Creates a new [Nkeys] instance from an Ed25519 key pair and prefix byte.
  ///
  /// Parameters:
  /// - [prefixByte] The prefix byte identifying the key type (user, account, server etc)
  /// - [keyPair] The Ed25519 key pair used for signing and verification
  ///
  /// Throws:
  /// - [NkeysException] if the prefix byte is invalid
  ///
  /// Example:
  /// ```dart
  /// final keyPair = ed.generateKey();
  /// final keys = Nkeys(PrefixByteUser, keyPair);
  /// ```
  ///
  /// See also:
  /// * [newNkeys] - Generates new random keys with a prefix
  /// * [fromSeed] - Creates keys from a seed string
  /// * [PrefixByteUser] - Prefix for user keys
  Nkeys(this.prefixByte, this.keyPair) {
    if (!_checkValidPrefixByte(prefixByte)) {
      throw NkeysException('invalid prefix byte $prefixByte');
    }
  }

  /// Generates a new [Nkeys] instance with a random Ed25519 key pair.
  ///
  /// Creates a new random Ed25519 key pair and wraps it in an [Nkeys] instance
  /// with the specified prefix byte.
  ///
  /// Parameters:
  /// - [prefixByte] The prefix byte identifying the key type (user, account, server etc)
  ///
  /// Returns:
  /// A new [Nkeys] instance containing the generated key pair.
  ///
  /// Throws:
  /// - [NkeysException] if the prefix byte is invalid
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.newNkeys(PrefixByteUser);
  /// ```
  ///
  /// See also:
  /// * [createUser] - Creates user-specific keys
  /// * [createAccount] - Creates account-specific keys
  /// * [createOperator] - Creates operator-specific keys
  /// * [fromSeed] - Creates keys from an existing seed
  static Nkeys newNkeys(int prefixByte) {
    var kp = ed.generateKey();

    return Nkeys(prefixByte, kp);
  }

  /// Creates a new [Nkeys] instance from an encoded seed string.
  ///
  /// Decodes the base32-encoded [seed] string and extracts the prefix byte and raw seed data.
  /// Creates an Ed25519 key pair from the raw seed and wraps it in a new [Nkeys] instance.
  ///
  /// Parameters:
  /// - [seed] A base32-encoded seed string containing prefix and key data
  ///
  /// Returns:
  /// A new [Nkeys] instance initialized with the key pair derived from the seed.
  ///
  /// Throws:
  /// - [NkeysException] if the seed has an invalid prefix byte
  /// - [NkeysException] if the public key prefix is invalid
  ///
  /// Example:
  /// ```dart
  /// final seed = 'SUAGM3GK4MGKG2CF6IKP4IBXLZ5PRSRQCJ74RLRQGY6WWZB45NFA====';
  /// final keys = Nkeys.fromSeed(seed);
  /// ```
  ///
  /// See also:
  /// * [newNkeys] - Creates keys with random seed
  /// * [PrefixByteSeed] - Expected prefix for seeds
  /// * [seed] - Gets the encoded seed string
  static Nkeys fromSeed(String seed) {
    var raw = base32.decode(seed);

    // Need to do the reverse here to get back to internal representation.
    var b1 = raw[0] & 248; // 248 = 11111000
    var b2 = ((raw[0] & 7) << 5) | ((raw[1] & 248) >> 3); // 7 = 00000111

    if (b1 != PrefixByteSeed) {
      throw Exception(NkeysException('not seed prefix byte'));
    }
    if (_checkValidPublicPrefixByte(b2) == PrefixByteUnknown) {
      throw Exception(NkeysException('not public prefix byte'));
    }

    var rawSeed = raw.sublist(2, 34);
    var key = ed.newKeyFromSeed(rawSeed);
    var kp = ed.KeyPair(key, ed.public(key));

    return Nkeys(b2, kp);
  }

  /// Creates a new [Nkeys] key pair with the specified prefix byte.
  ///
  /// Generates a new random Ed25519 key pair and wraps it in a [Nkeys] instance
  /// with the given [prefix] byte.
  ///
  /// Parameters:
  /// - [prefix] The prefix byte indicating the key type (e.g. [PrefixByteUser], [PrefixByteAccount])
  ///
  /// Returns:
  /// A new [Nkeys] instance containing the generated key pair.
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.createPair(PrefixByteUser);
  /// ```
  ///
  /// See also:
  /// * [createUser] - Creates a user key pair
  /// * [createAccount] - Creates an account key pair
  /// * [createOperator] - Creates an operator key pair
  /// * [PrefixByteUser], [PrefixByteAccount], [PrefixByteOperator] - Valid prefix bytes
  static Nkeys createPair(int prefix) {
    var kp = ed.generateKey();
    return Nkeys(prefix, kp);
  }

  /// Creates a new NATS user key pair.
  ///
  /// Generates a new Ed25519 key pair with the [PrefixByteUser] prefix byte,
  /// suitable for NATS user authentication.
  ///
  /// Returns:
  /// A new [Nkeys] instance containing the generated user key pair.
  ///
  /// Example:
  /// ```dart
  /// final userKeys = Nkeys.createUser();
  /// final publicKey = userKeys.publicKey();
  /// ```
  ///
  /// See also:
  /// * [createAccount] - Creates an account key pair
  /// * [createOperator] - Creates an operator key pair
  /// * [createPair] - Creates a key pair with a custom prefix
  /// * [PrefixByteUser] - The prefix byte used for user keys
  static Nkeys createUser() {
    return createPair(PrefixByteUser);
  }

  /// Creates a new NATS account key pair.
  ///
  /// Generates a new Ed25519 key pair with the [PrefixByteAccount] prefix byte,
  /// suitable for NATS account authentication.
  ///
  /// Returns:
  /// A new [Nkeys] instance containing the generated account key pair.
  ///
  /// Example:
  /// ```dart
  /// final accountKeys = Nkeys.createAccount();
  /// final publicKey = accountKeys.publicKey();
  /// ```
  ///
  /// See also:
  /// * [createUser] - Creates a user key pair
  /// * [createOperator] - Creates an operator key pair
  /// * [createPair] - Creates a key pair with a custom prefix
  /// * [PrefixByteAccount] - The prefix byte used for account keys
  static Nkeys createAccount() {
    return createPair(PrefixByteAccount);
  }

  /// Creates a new NATS operator key pair.
  ///
  /// Generates a new Ed25519 key pair with the [PrefixByteOperator] prefix byte,
  /// suitable for NATS operator authentication.
  ///
  /// Returns:
  /// A new [Nkeys] instance containing the generated operator key pair.
  ///
  /// Example:
  /// ```dart
  /// final operatorKeys = Nkeys.createOperator();
  /// final publicKey = operatorKeys.publicKey();
  /// ```
  ///
  /// See also:
  /// * [createUser] - Creates a user key pair
  /// * [createAccount] - Creates an account key pair
  /// * [createPair] - Creates a key pair with a custom prefix
  /// * [PrefixByteOperator] - The prefix byte used for operator keys
  static Nkeys createOperator() {
    return createPair(PrefixByteOperator);
  }

  /// Returns the encoded seed string for this key pair
  String get seed {
    return _encodeSeed(prefixByte, rawSeed);
  }

  /// Gets the encoded public key string for this key pair.
  ///
  /// Returns the public key encoded with the appropriate prefix byte and base32 encoded.
  /// The prefix byte identifies the key type (user, account, server etc).
  ///
  /// Returns:
  /// A base32 encoded string containing the prefixed public key.
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.createUser();
  /// final pubKey = keys.publicKey(); // Returns string like "UD..."
  /// ```
  ///
  /// See also:
  /// * [rawPublicKey] - Gets the raw public key bytes
  /// * [privateKey] - Gets the encoded private key
  /// * [verify] - Verifies signatures using this public key
  String publicKey() {
    return _encode(prefixByte, keyPair.publicKey.bytes);
  }

  /// Gets the raw public key bytes without any prefix or encoding.
  ///
  /// Returns the raw 32-byte Ed25519 public key used for signature verification.
  /// This is different from [publicKey] which returns an encoded string with prefix.
  ///
  /// Returns:
  /// A [List<int>] containing the 32-byte raw public key value.
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.createUser();
  /// final rawPubKey = keys.rawPublicKey(); // Returns raw 32 bytes
  /// ```
  ///
  /// See also:
  /// * [publicKey] - Gets the encoded public key string
  /// * [verify] - Verifies signatures using this public key
  /// * [ed.PublicKey] - The underlying Ed25519 public key
  List<int> rawPublicKey() {
    return keyPair.publicKey.bytes;
  }

  /// Gets the encoded private key string for this key pair.
  ///
  /// Returns the private key encoded with the [PrefixBytePrivate] prefix and base32 encoded.
  /// The private key contains both the seed and public key data needed for signing.
  ///
  /// Returns:
  /// A base32 encoded string containing the prefixed private key.
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.createUser();
  /// final privKey = keys.privateKey(); // Returns string like "PD..."
  /// ```
  ///
  /// See also:
  /// * [rawPrivateKey] - Gets the raw private key bytes
  /// * [seed] - Gets the encoded seed string
  /// * [sign] - Signs messages using this private key
  /// * [PrefixBytePrivate] - Prefix used for private keys
  String privateKey() {
    return _encode(PrefixBytePrivate, keyPair.privateKey.bytes);
  }

  /// Gets the raw private key bytes without any prefix or encoding.
  ///
  /// Returns the raw 64-byte Ed25519 private key used for signing. This is different
  /// from [privateKey] which returns an encoded string with prefix.
  ///
  /// Returns:
  /// A [List<int>] containing the 64-byte raw private key value.
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.createUser();
  /// final rawPrivKey = keys.rawPrivateKey(); // Returns raw 64 bytes
  /// ```
  ///
  /// See also:
  /// * [privateKey] - Gets the encoded private key string
  /// * [sign] - Signs messages using this private key
  /// * [ed.PrivateKey] - The underlying Ed25519 private key
  List<int> rawPrivateKey() {
    return keyPair.privateKey.bytes;
  }

  /// Signs a message using this key pair's private key.
  ///
  /// Uses Ed25519 to sign the message bytes with this key pair's private key.
  /// The signature can be verified using [verify] with the corresponding public key.
  ///
  /// Parameters:
  /// - [message] The message bytes to sign
  ///
  /// Returns:
  /// A [List<int>] containing the Ed25519 signature bytes.
  ///
  /// Example:
  /// ```dart
  /// final keys = Nkeys.createUser();
  /// final message = utf8.encode('Hello');
  /// final signature = keys.sign(message);
  /// ```
  ///
  /// See also:
  /// * [verify] - Verifies signatures created by this method
  /// * [rawPrivateKey] - Gets the private key used for signing
  /// * [ed.sign] - The underlying Ed25519 signing function
  List<int> sign(List<int> message) {
    var msg = Uint8List.fromList(message);
    var r = List<int>.from(ed.sign(keyPair.privateKey, msg));
    return r;
  }

  /// Verifies a signature using a public key.
  ///
  /// Uses Ed25519 to verify that the signature was created by the private key 
  /// corresponding to [publicKey]. The signature must have been created by [sign]
  /// with the matching private key.
  ///
  /// Parameters:
  /// - [publicKey] The encoded public key string to verify against
  /// - [message] The original message that was signed
  /// - [signature] The signature to verify
  ///
  /// Returns:
  /// - `true` if the signature is valid for this public key and message
  /// - `false` if verification fails
  ///
  /// Throws:
  /// - [NkeysException] if the public key is invalid or malformed
  ///
  /// Example:
  /// ```dart
  /// final pubKey = keys.publicKey;
  /// final message = utf8.encode('Hello');
  /// final signature = keys.sign(message);
  /// final valid = Nkeys.verify(pubKey, message, signature);
  /// ```
  ///
  /// See also:
  /// * [sign] - Creates signatures that can be verified by this method
  /// * [ed.verify] - The underlying Ed25519 verification function
  static bool verify(String publicKey, List<int> message, List<int> signature) {
    var r = _decode(publicKey);
    var prefix = r[0][0];
    if (!_checkValidPrefixByte(prefix)) {
      throw NkeysException('Ivalid Public key');
    }

    var pub = r[1].toList();
    if (pub.length < ed.PublicKeySize) {
      throw NkeysException('Ivalid Public key');
    }
    while (pub.length > ed.PublicKeySize) {
      pub.removeLast();
    }
    return ed.verify(ed.PublicKey(pub), Uint8List.fromList(message),
        Uint8List.fromList(signature));
  }

  /// Decodes an encoded key string and validates it has the expected prefix byte.
  ///
  /// Takes an encoded key string and decodes it, validating that the prefix byte matches
  /// the expected prefix type (e.g. user, account, server etc). This is used to ensure
  /// a key is of the correct type before using it.
  ///
  /// Parameters:
  /// - [expectPrefix] The prefix byte value that is expected (e.g. [PrefixByteUser])
  /// - [src] The encoded key string to decode
  ///
  /// Returns:
  /// The decoded key bytes without the prefix byte.
  ///
  /// Throws:
  /// - [NkeysException] if the decoded key's prefix does not match the expected prefix
  ///
  /// Example:
  /// ```dart
  /// final bytes = Nkeys.decode(PrefixByteUser, encodedKey);
  /// ```
  ///
  /// See also:
  /// * [PrefixByteUser], [PrefixByteAccount] etc - Valid prefix byte constants
  /// * [_decode] - Internal decoding function used by this method
  static Uint8List decode(int expectPrefix, String src) {
    var res = _decode(src);
    if (res[0][0] != expectPrefix) {
      throw NkeysException('encode invalid prefix');
    }
    return res[1];
  }
}

/// Decodes an encoded key string into its components.
///
/// Takes a base32 encoded key string and decodes it into:
/// - [0] The prefix byte indicating the key type
/// - [1] The decoded key data bytes
/// - [2] For seed keys only: The original key type byte
///
/// The prefix byte will be one of:
/// - [PrefixByteSeed] for seed keys
/// - [PrefixByteUnknown] if the prefix is not recognized
/// - A valid key type prefix ([PrefixByteUser], [PrefixByteAccount], etc)
///
/// For seed keys, the original key type is preserved in component [2].
/// This allows reconstructing the full key information.
///
/// Returns a list of [Uint8List] containing the decoded components.
///
/// See also:
/// * [decode] - Public decoding method that validates prefix bytes
/// * [PrefixByteSeed] - Prefix byte for seed keys
/// * [PrefixByteUnknown] - Prefix byte for unknown key types
List<Uint8List> _decode(String src) {
  var b = base32.decode(src).toList();
  var ret = <Uint8List>[];

  var prefix = b[0];
  if (_checkValidPrefixByte(prefix)) {
    ret.add(Uint8List.fromList([prefix]));
    b.removeAt(0);
    ret.add(Uint8List.fromList(b));
    return ret;
  }

  // Might be a seed.
  // Need to do the reverse here to get back to internal representation.
  var b1 = b[0] & 248; // 248 = 11111000
  var b2 = ((b[0] & 7) << 5) | ((b[1] & 248) >> 3); // 7 = 00000111

  if (b1 == PrefixByteSeed) {
    ret.add(Uint8List.fromList([PrefixByteSeed]));
    b.removeAt(0);
    b.removeAt(0);
    ret.add(Uint8List.fromList(b));
    ret.add(Uint8List.fromList([b2]));
    return ret;
  }

  ret.add(Uint8List.fromList([PrefixByteUnknown]));
  b.removeAt(0);
  ret.add(Uint8List.fromList(b));
  return ret;
}

/// Validates and returns a public key prefix byte.
///
/// Checks if the given prefix byte represents a valid public key type:
/// - [PrefixByteServer] for server keys
/// - [PrefixByteCluster] for cluster keys 
/// - [PrefixByteOperator] for operator keys
/// - [PrefixByteAccount] for account keys
/// - [PrefixByteUser] for user keys
///
/// Returns:
/// - The original prefix if valid
/// - [PrefixByteUnknown] if the prefix is not a valid public key type
///
/// Example:
/// ```dart
/// final prefix = _checkValidPublicPrefixByte(PrefixByteUser); 
/// // Returns PrefixByteUser
/// 
/// final unknown = _checkValidPublicPrefixByte(PrefixByteSeed);
/// // Returns PrefixByteUnknown
/// ```
///
/// See also:
/// * [_checkValidPrefixByte] - Validates all prefix types including private/seed
/// * [PrefixByteUnknown] - Returned for invalid prefixes
int _checkValidPublicPrefixByte(int prefix) {
  switch (prefix) {
    case PrefixByteServer:
    case PrefixByteCluster:
    case PrefixByteOperator:
    case PrefixByteAccount:
    case PrefixByteUser:
      return prefix;
  }
  return PrefixByteUnknown;
}

/// Validates if a prefix byte represents a valid NATS key type.
///
/// Checks if the given prefix byte represents any valid NATS key type:
/// - [PrefixByteOperator] for operator keys
/// - [PrefixByteServer] for server keys
/// - [PrefixByteCluster] for cluster keys
/// - [PrefixByteAccount] for account keys
/// - [PrefixByteUser] for user keys
/// - [PrefixByteSeed] for seed keys
/// - [PrefixBytePrivate] for private keys
///
/// Parameters:
/// - [prefix] The prefix byte to validate
///
/// Returns:
/// - `true` if the prefix is valid
/// - `false` if the prefix is not a valid NATS key type
///
/// Example:
/// ```dart
/// final isValid = _checkValidPrefixByte(PrefixByteUser); // Returns true
/// final invalid = _checkValidPrefixByte(123); // Returns false
/// ```
///
/// See also:
/// * [_checkValidPublicPrefixByte] - Validates only public key prefixes
/// * [PrefixByteUnknown] - Used for invalid/unknown prefixes
bool _checkValidPrefixByte(int prefix) {
  switch (prefix) {
    case PrefixByteOperator:
    case PrefixByteServer:
    case PrefixByteCluster:
    case PrefixByteAccount:
    case PrefixByteUser:
    case PrefixByteSeed:
    case PrefixBytePrivate:
      return true;
  }
  return false;
}

/// Encodes a key with a prefix byte into a base32 encoded string.
///
/// Takes a prefix byte identifying the key type and raw key bytes, adds a CRC16
/// checksum, and base32 encodes the result. The prefix byte is validated before
/// encoding.
///
/// Parameters:
/// - [prefix] The prefix byte identifying the key type (user, account, server etc)
/// - [src] The raw key bytes to encode
///
/// Returns:
/// A base32 encoded string containing the prefixed and checksummed key.
///
/// Throws:
/// - [NkeysException] if the prefix byte is invalid
///
/// Example:
/// ```dart
/// final encoded = _encode(PrefixByteUser, keyBytes);
/// ```
///
/// See also:
/// * [_decode] - Decodes strings encoded by this method
/// * [_checkValidPrefixByte] - Validates prefix bytes
/// * [_crc16] - Calculates checksum used by this method
String _encode(int prefix, List<int> src) {
  if (!_checkValidPrefixByte(prefix)) {
    throw NkeysException('encode invalid prefix');
  }

  var raw = [prefix];
  raw.addAll(src);

  // Calculate and write crc16 checksum
  raw.addAll(_crc16(raw));
  var bytes = Uint8List.fromList(raw);

  return _b32Encode(bytes);
}


/// Calculates a CRC-16 checksum for a byte array using CCITT polynomial.
///
/// Uses the CCITT polynomial (0x1021) and XMODEM initialization value (0x0000)
/// to generate a 16-bit CRC checksum. The checksum is returned as a 2-byte
/// Uint8List in little-endian byte order.
///
/// Parameters:
/// - [bytes] The input bytes to calculate the checksum for
///
/// Returns:
/// A [Uint8List] containing the 2-byte CRC-16 checksum in little-endian order.
///
/// Example:
/// ```dart
/// final data = [1, 2, 3, 4];
/// final checksum = _crc16(data); // Returns 2-byte checksum
/// ```
///
/// See also:
/// * [_encode] - Uses this checksum in key encoding
/// * [_encodeSeed] - Uses this checksum in seed encoding
Uint8List _crc16(List<int> bytes) {
  // CCITT
  const POLYNOMIAL = 0x1021;
  // XMODEM
  const INIT_VALUE = 0x0000;

  final bitRange = Iterable.generate(8);

  var crc = INIT_VALUE;
  for (var byte in bytes) {
    crc ^= (byte << 8);
    // ignore: unused_local_variable
    for (var i in bitRange) {
      crc = (crc & 0x8000) != 0 ? (crc << 1) ^ POLYNOMIAL : crc << 1;
    }
  }
  var byteData = ByteData(2)..setUint16(0, crc, Endian.little);
  return byteData.buffer.asUint8List();
}

/// Encodes a raw key into a base32-encoded seed string with prefix and checksum.
///
/// Takes a raw 32-byte key and encodes it into a NATS seed format by:
/// 1. Adding the seed prefix byte and public key type prefix
/// 2. Appending the raw key bytes
/// 3. Calculating and appending a CRC-16 checksum
/// 4. Base32 encoding the entire byte sequence
///
/// Parameters:
/// - [public] The prefix byte indicating the public key type (user, account etc)
/// - [src] The 32-byte raw key to encode
///
/// Returns:
/// A base32-encoded string containing the prefixed and checksummed seed.
///
/// Throws:
/// - [NkeysException] if the public prefix byte is invalid
/// - [NkeysException] if the source key length is not 32 bytes
///
/// Example:
/// ```dart
/// final seed = _encodeSeed(PrefixByteUser, rawKey);
/// // Returns base32 string like "SUAML5Q..."
/// ```
///
/// See also:
/// * [_crc16] - Calculates the checksum
/// * [_b32Encode] - Performs the base32 encoding
/// * [PrefixByteSeed] - The seed prefix byte
String _encodeSeed(int public, List<int> src) {
  if (_checkValidPublicPrefixByte(public) == PrefixByteUnknown) {
    throw NkeysException('Invalid public prefix byte');
  }

  if (src.length != 32) {
    throw NkeysException('Invalid src langth');
  }

  // In order to make this human printable for both bytes, we need to do a little
  // bit manipulation to setup for base32 encoding which takes 5 bits at a time.
  var b1 = PrefixByteSeed | ((public) >> 5);
  var b2 = ((public) & 31) << 3; // 31 = 00011111

  var raw = [b1, b2];

  raw.addAll(src);

  // Calculate and write crc16 checksum
  raw.addAll(_crc16(raw));

  return _b32Encode(raw);
}

/// Encodes bytes using base32 encoding without padding.
///
/// Takes a list of bytes and encodes them using base32 encoding, removing any
/// padding '=' characters from the output. This produces a clean base32 string
/// suitable for use in NATS keys.
///
/// Parameters:
/// - [bytes] The raw bytes to encode
///
/// Returns:
/// A base32-encoded string with padding removed.
///
/// Example:
/// ```dart
/// final encoded = _b32Encode([1, 2, 3]);
/// // Returns string like "AEBAG"
/// ```
///
/// See also:
/// * [base32.encode] - The underlying base32 encoding function
/// * [_encodeSeed] - Uses this to encode seed bytes
String _b32Encode(List<int> bytes) {
  var b = Uint8List.fromList(bytes);
  var str = base32.encode(b).replaceAll(RegExp('='), '');
  return str;
}
