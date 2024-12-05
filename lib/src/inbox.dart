import 'dart:math';
import 'dart:typed_data';

var _nuid = Nuid();

/// Generates a unique inbox subject name for request-reply messaging.
///
/// Creates a unique subject name by combining the optional [inboxPrefix] with a
/// cryptographically secure random string when [secure] is true, or a pseudo-random
/// string otherwise.
///
/// Parameters:
/// - [inboxPrefix] - Optional prefix for the inbox name, defaults to '_INBOX'
/// - [secure] - Whether to use cryptographically secure random generation,
///   defaults to true
///
/// Returns a unique inbox subject string that can be used for request-reply messaging.
///
/// Example:
/// ```dart
/// final inbox = newInbox(); // Returns something like '_INBOX.a1b2c3d4'
/// final customInbox = newInbox(inboxPrefix: 'MYAPP'); // Returns 'MYAPP.a1b2c3d4'
/// ```
String newInbox({String inboxPrefix = '_INBOX', bool secure = true}) {
  if (secure) {
    _nuid = Nuid();
  }
  return inboxPrefix + _nuid.next();
}

/// A utility class for generating unique identifiers (NUIDs) for NATS messaging.
///
/// This is a port of the NUID (Nano Unique IDentifier) implementation from Go NATS.
/// It generates unique identifiers that are fast, safe and minimize collisions by combining
/// a pre-randomized prefix with an auto-incrementing sequence.
///
/// The generated IDs:
/// - Are 22 characters long
/// - Use a base62 encoding (0-9, A-Z, a-z)
/// - Have a 12 character random prefix that is periodically regenerated
/// - Include a 10 character sequential component
///
/// Example:
/// ```dart
/// final nuid = Nuid();
/// final id = nuid.next(); // Returns something like "ABCDEFGHIJKL0123456789"
/// ```
///
/// See also:
/// * [newInbox] - Uses this class to generate unique inbox subjects
/// * The original Go implementation at https://github.com/nats-io/nuid
class Nuid {
  static const _digits =
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  static const _base = 62;
  static const _maxSeq = 839299365868340224; // base^seqLen == 62^10;
  static const _minInc = 33;
  static const _maxInc = 333;
  static const _preLen = 12;
  static const _seqLen = 10;
  static const _totalLen = _preLen + _seqLen;

  late Uint8List _pre; // check initial
  late int _seq;
  late int _inc;

  static final Nuid _nuid = Nuid._createInstance();

  Nuid._createInstance() {
    randomizePrefix();
    resetSequential();
  }

  /// Creates a new [Nuid] instance with a randomized prefix and sequential counter.
  ///
  /// The constructor initializes a new NUID generator by:
  /// - Generating a random 12-character prefix using [randomizePrefix]
  /// - Setting up the sequential counter using [resetSequential]
  ///
  /// Example:
  /// ```dart
  /// final nuid = Nuid();
  /// final id = nuid.next(); // Generates a unique ID
  /// ```
  ///
  /// See also:
  /// * [getInstance] - Gets the singleton instance
  /// * [next] - Generates the next unique ID
  Nuid() {
    randomizePrefix();
    resetSequential();
  }

  /// Gets the singleton instance of [Nuid].
  ///
  /// Returns the global shared [Nuid] instance that can be used across the application.
  /// This is useful when you want to ensure all IDs are generated from the same sequence.
  ///
  /// Example:
  /// ```dart
  /// final nuid = Nuid.getInstance();
  /// final id = nuid.next(); // Gets next ID from shared instance
  /// ```
  ///
  /// See also:
  /// * [Nuid] constructor - Creates a new independent instance
  /// * [next] - Generates the next unique ID
  static getInstance() {
    return _nuid;
  }

  /// Generates the next unique NUID (Network Unique Identifier).
  ///
  /// Updates the internal sequential counter and regenerates the prefix if needed
  /// to ensure uniqueness. The resulting NUID is encoded as a base62 string.
  ///
  /// The NUID consists of:
  /// - A random 12-character prefix
  /// - A sequential counter encoded in base62
  ///
  /// Example:
  /// ```dart
  /// final nuid = Nuid();
  /// final id = nuid.next(); // Returns something like "ABCD1234EFGH"
  /// ```
  ///
  /// Returns a string containing the next unique NUID.
  ///
  /// See also:
  /// * [randomizePrefix] - Generates a new random prefix
  /// * [resetSequential] - Resets the sequential counter
  String next() {
    _seq = _seq + _inc;
    if (_seq >= _maxSeq) {
      randomizePrefix();
      resetSequential();
    }
    var s = _seq;
    var b = List<int>.from(_pre);
    b.addAll(Uint8List(_seqLen));
    for (int? i = _totalLen, l = s; i! > _preLen; l = l ~/ _base) {
      i -= 1;
      b[i] = _digits.codeUnits[l! % _base];
    }
    return String.fromCharCodes(b);
  }

  /// Resets the sequential counter to a new random value.
  ///
  /// Generates a new random sequential counter and increment value using a
  /// cryptographically secure random number generator. The new counter value
  /// is guaranteed to be within the valid range (less than [_maxSeq]).
  ///
  /// The increment value is randomly chosen between [_minInc] and [_maxInc]
  /// to help ensure uniqueness of generated IDs.
  ///
  /// Example:
  /// ```dart
  /// final nuid = Nuid();
  /// nuid.resetSequential(); // Resets to new random counter
  /// ```
  ///
  /// See also:
  /// * [next] - Generates the next unique ID
  /// * [randomizePrefix] - Generates a new random prefix
  void resetSequential() {
    Random();
    var _rng = Random.secure();

    _seq = _rng.nextInt(1 << 31) << 32 | _rng.nextInt(1 << 31);
    if (_seq > _maxSeq) {
      _seq = _seq % _maxSeq;
    }
    _inc = _minInc + _rng.nextInt(_maxInc - _minInc);
  }

  /// Generates a new random prefix for the NUID.
  ///
  /// Uses a cryptographically secure random number generator to create a new
  /// prefix of length [_preLen]. Each character in the prefix is randomly 
  /// selected from the allowed digit set.
  ///
  /// The prefix helps ensure uniqueness of generated IDs across multiple
  /// processes or machines.
  ///
  /// Example:
  /// ```dart
  /// final nuid = Nuid();
  /// nuid.randomizePrefix(); // Generates new random prefix
  /// ```
  ///
  /// See also:
  /// * [next] - Generates the next unique ID using this prefix
  /// * [resetSequential] - Resets the sequential counter
  void randomizePrefix() {
    _pre = Uint8List(_preLen);
    var _rng = Random.secure();
    for (var i = 0; i < _preLen; i++) {
      var n = _rng.nextInt(255) % _base;
      _pre[i] = _digits.codeUnits[n];
    }
  }
}
