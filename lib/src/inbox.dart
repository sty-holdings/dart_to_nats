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

///nuid port from go nats
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

  ///constructure
  Nuid() {
    randomizePrefix();
    resetSequential();
  }

  /// get instance
  static getInstance() {
    return _nuid;
  }

  ///generate next nuid
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

  ///reset sequential
  void resetSequential() {
    Random();
    var _rng = Random.secure();

    _seq = _rng.nextInt(1 << 31) << 32 | _rng.nextInt(1 << 31);
    if (_seq > _maxSeq) {
      _seq = _seq % _maxSeq;
    }
    _inc = _minInc + _rng.nextInt(_maxInc - _minInc);
  }

  ///random new prefix
  void randomizePrefix() {
    _pre = Uint8List(_preLen);
    var _rng = Random.secure();
    for (var i = 0; i < _preLen; i++) {
      var n = _rng.nextInt(255) % _base;
      _pre[i] = _digits.codeUnits[n];
    }
  }
}
