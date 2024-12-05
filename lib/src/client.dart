import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mutex/mutex.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'common.dart';
import 'inbox.dart';
import 'message.dart';
import 'nkeys.dart';
import 'subscription.dart';


enum _ReceiveState {
  idle, //op=msg -> msg
  msg, //newline -> idle
}

/// Represents the current connection status of the NATS client.
///
/// The status transitions through different states during connection lifecycle:
/// - [Status.disconnected]: Initial state or when connection is lost
/// - [Status.connecting]: Actively trying to establish first connection
/// - [Status.reconnecting]: Attempting to reconnect after disconnect
/// - [Status.tlsHandshake]: Performing TLS handshake for secure connections
/// - [Status.infoHandshake]: Exchanging initial info with server
/// - [Status.connected]: Successfully connected and ready for operations
/// - [Status.closed]: Connection permanently closed
enum Status {
  /// disconnected or not connected
  disconnected,

  /// tlsHandshake
  tlsHandshake,

  /// channel layer connect wait for info connect handshake
  infoHandshake,

  ///connected to server ready
  connected,

  ///already close by close or server
  closed,

  ///automatic reconnection to server
  reconnecting,

  ///connecting by connect() method
  connecting,

  // draining_subs,
  // draining_pubs,
}

enum _ClientStatus {
  init,
  used,
  closed,
}

class _Pub {
  final String? subject;
  final List<int> data;
  final String? replyTo;

  _Pub(this.subject, this.data, this.replyTo);
}

/// A NATS client that handles connections to NATS servers and provides pub/sub functionality.
///
/// The client supports:
/// - Multiple transport protocols (WebSocket, TCP, TLS)
/// - Automatic reconnection
/// - JSON encoding/decoding
/// - Request-reply pattern
/// - Message headers
/// - Queue groups
/// - TLS/SSL security
///
/// Example usage:
/// ```dart
/// final client = Client();
/// await client.connect(Uri.parse('nats://localhost:4222'));
///
/// // Subscribe to messages
/// final sub = client.sub('foo');
/// sub.stream.listen((msg) => print('Received: ${msg.data}'));
///
/// // Publish messages
/// client.pubString('foo', 'Hello NATS!');
///
/// // Make request
/// final response = await client.requestString('service', 'request');
///
/// // Close when done
/// await client.close();
/// ```
class Client {
  var _ackStream = StreamController<bool>.broadcast();
  _ClientStatus _clientStatus = _ClientStatus.init;
  WebSocketChannel? _wsChannel; 
  Socket? _tcpSocket;
  SecureSocket? _secureSocket;
  bool _tlsRequired = false;
  bool _retry = false;

  late Info _info;
  late Completer _pingCompleter;
  late Completer _connectCompleter;
  
  /// Handler function for WebSocket connection errors.
  ///
  /// By default, throws a [NatsException] with the error message.
  /// Can be overridden to provide custom error handling behavior.
  ///
  /// The handler receives the error object as a parameter.
  /// ```dart
  /// client.wsErrorHandler = (error) {
  ///   print('WebSocket error: $error');
  ///   // Custom error handling...
  /// };
  /// ```
  Function(dynamic) wsErrorHandler = (e) {
    throw NatsException('listen ws error: $e');
  };

  Status _status = Status.disconnected;

  /// Returns whether the client is currently connected to a NATS server.
  ///
  /// Returns `true` if the client's status is [Status.connected], `false` otherwise.
  /// This can be used to check the connection state before performing operations.
  /// ```dart
  /// if (client.connected) {
  ///   client.pubString('foo', 'message');
  /// }
  /// ```
  bool get connected => _status == Status.connected;

  final _statusController = StreamController<Status>.broadcast();

  StreamController _channelStream = StreamController();

  /// Gets the current status of the NATS client connection.
  ///
  /// Returns a [Status] enum value indicating the current state:
  /// - [Status.disconnected] - Not connected to any server
  /// - [Status.tlsHandshake] - Performing TLS handshake
  /// - [Status.infoHandshake] - Performing initial INFO handshake
  /// - [Status.connected] - Successfully connected and ready
  /// - [Status.closed] - Connection has been closed
  /// - [Status.reconnecting] - Attempting to reconnect
  /// - [Status.connecting] - Initial connection attempt
  Status get status => _status;

  /// Whether to accept invalid/self-signed SSL certificates.
  ///
  /// When set to `true`, the client will accept invalid or self-signed SSL certificates
  /// during TLS handshakes. This is useful for development and testing, but should
  /// **not** be used in production as it bypasses security checks.
  ///
  /// ```dart
  /// final client = Client()
  ///   ..acceptBadCert = true; // Only for development/testing
  /// ```
  /// 
  /// Defaults to `false`.
  bool acceptBadCert = false;

  /// Stream of [Status] updates for monitoring the client's connection state.
  ///
  /// This stream emits [Status] events whenever the client's connection state changes.
  /// Listeners can use this to react to connection changes like disconnects or reconnects.
  ///
  /// ```dart
  /// client.statusStream.listen((status) {
  ///   switch (status) {
  ///     case Status.connected:
  ///       print('Connected to NATS server');
  ///       break;
  ///     case Status.disconnected:
  ///       print('Lost connection to server');
  ///       break;
  ///     // Handle other status changes...
  ///   }
  /// });
  /// ```
  Stream<Status> get statusStream => _statusController.stream;

  ConnectOption _connectOption = ConnectOption();

  /// The security context used for TLS/SSL connections.
  ///
  /// This allows configuring certificates and keys for secure connections:
  /// ```dart
  /// final context = SecurityContext()
  ///   ..setTrustedCertificates('rootCA.pem')
  ///   ..useCertificateChain('client-cert.pem')
  ///   ..usePrivateKey('client-key.pem');
  /// 
  /// final client = Client()
  ///   ..securityContext = context;
  /// ```
  /// 
  /// Can be null if TLS/SSL is not needed.
  /// 
  /// See also:
  /// * [connect] - Uses this context when establishing TLS connections
  /// * [acceptBadCert] - Related setting for certificate validation
  SecurityContext? securityContext;

  Nkeys? _nkeys;

  /// The seed value used for NATS authentication with NKeys.
  ///
  /// NKeys provides a public-key signature system for NATS authentication.
  /// The seed is used to generate key pairs for signing server challenges.
  ///
  /// Can be set to enable NKey-based auth:
  /// ```dart
  /// client.seed = 'SUAGM5PX4CUE...'; // Set NKey seed
  /// ```
  /// 
  /// Set to null to disable NKey authentication.
  /// 
  /// See also:
  /// * [Nkeys] - Handles NKey operations
  /// * [_sign] - Uses seed to sign server challenges
  String? get seed => _nkeys?.seed;
  set seed(String? newseed) {
    if (newseed == null) {
      _nkeys = null;
      return;
    }
    _nkeys = Nkeys.fromSeed(newseed);
  }

  final _jsonDecoder = <Type, dynamic Function(String)>{};
  // final _jsonEncoder = <Type, String Function(Type)>{};

  /// Creates a new NATS client instance.
  ///
  /// The client starts in a disconnected state. Call [connect] to establish
  /// a connection to a NATS server.
  ///
  /// Example:
  /// ```dart
  /// final client = Client();
  /// await client.connect(Uri.parse('nats://localhost:4222'));
  /// ```
  ///
  /// See also:
  /// * [connect] - Establishes connection to a NATS server
  /// * [close] - Closes the client connection
  /// * [Status] - Connection status values
  Client() {
    _streamHandle();
  }

  /// Adds a JSON decoder for a specific type.
  ///
  /// This method allows registering a custom JSON decoder for a given type.
  /// The decoder function converts a JSON string into an instance of the specified type.
  ///
  /// Example:
  /// ```dart
  /// client.registerJsonDecoder<Person>((json) => Person.fromJson(json));
  /// ```
  ///
  /// Parameters:
  /// - [f] The decoder function that takes a JSON string and returns an instance of type [T]
  ///
  /// Throws:
  /// - [NatsException] if attempting to register a decoder for dynamic type
  ///
  /// See also:
  /// * [Message] - Uses registered decoders to parse message payloads
  void registerJsonDecoder<T>(T Function(String) f) {
    if (T == dynamic) {
      NatsException('can not register dyname type');
    }
    _jsonDecoder[T] = f;
  }

  /// add json encoder for type <T>
  // void registerJsonEncoder<T>(String Function(T) f) {
  //   if (T == dynamic) {
  //     NatsException('can not register dyname type');
  //   }
  //   _jsonEncoder[T] = f as String Function(Type);
  // }

  /// Returns the current server information.
  ///
  /// Contains details about the connected NATS server including:
  /// - Server ID and version
  /// - Connection information
  /// - Server configuration
  /// - Authentication requirements
  ///
  /// Returns null if not connected to a server.
  ///
  /// See also:
  /// * [Info] - Server information data structure
  /// * [connect] - Establishes server connection and populates info
  Info? get info => _info;

  final _subs = <int, Subscription>{};
  final _backendSubs = <int, bool>{};
  final _pubBuffer = <_Pub>[];

  int _ssid = 0;

  List<int> _buffer = [];
  _ReceiveState _receiveState = _ReceiveState.idle;
  String _receiveLine1 = '';
  Future _sign() async {
    if (_info.nonce != null && _nkeys != null) {
      var sig = _nkeys?.sign(utf8.encode(_info.nonce!));

      _connectOption.sig = base64.encode(sig!);
    }
  }

  void _streamHandle() {
    _channelStream.stream.listen((d) {
      _buffer.addAll(d);
      // org code
      // while (
      //     _receiveState == _ReceiveState.idle && _buffer.contains(13)) {
      //   _processOp();
      // }

      //Thank aktxyz for contribution
      while (_receiveState == _ReceiveState.idle && _buffer.contains(13)) {
        var n13 = _buffer.indexOf(13);
        var msgFull =
            String.fromCharCodes(_buffer.take(n13)).toLowerCase().trim();
        var msgList = msgFull.split(' ');
        var msgType = msgList[0];
        //print('... process $msgType ${_buffer.length}');

        if (msgType == 'msg' || msgType == 'hmsg') {
          var len = int.parse(msgList.last);
          if (len > 0 && _buffer.length < (msgFull.length + len + 4)) {
            break; // not a full payload, go around again
          }
        }

        _processOp();
      }
      // }, onDone: () {
      //   _setStatus(Status.disconnected);
      //   close();
      // }, onError: (err) {
      //   _setStatus(Status.disconnected);
      //   close();
    });
  }

  /// Establishes a connection to a NATS server at the specified URI.
  ///
  /// Parameters:
  /// - [uri] - The URI of the NATS server to connect to (e.g. nats://localhost:4222)
  /// - [connectOption] - Optional configuration for the connection
  /// - [timeout] - Connection timeout in seconds (default: 5)
  /// - [retry] - Whether to retry failed connections (default: true)
  /// - [retryInterval] - Seconds between retry attempts (default: 10)
  /// - [retryCount] - Number of retry attempts (-1 for infinite, default: 3)
  /// - [securityContext] - Optional SSL/TLS security context for secure connections
  ///
  /// Throws:
  /// - [NatsException] if client is already in use
  /// - Error if client status is not disconnected/closed
  ///
  /// Example:
  /// ```dart
  /// final client = Client();
  /// await client.connect(Uri.parse('nats://localhost:4222'));
  /// ```
  Future connect(
    Uri uri, {
    ConnectOption? connectOption,
    int timeout = 5,
    bool retry = true,
    int retryInterval = 10,
    int retryCount = 3,
    SecurityContext? securityContext,
  }) async {
    this._retry = retry;
    this.securityContext = securityContext;
    _connectCompleter = Completer();
    if (_clientStatus == _ClientStatus.used) {
      throw Exception(
          NatsException('client in use. must close before call connect'));
    }
    if (status != Status.disconnected && status != Status.closed) {
      return Future.error('Error: status not disconnected and not closed');
    }
    _clientStatus = _ClientStatus.used;
    if (connectOption != null) _connectOption = connectOption;
    do {
      _connectLoop(
        uri,
        timeout: timeout,
        retryInterval: retryInterval,
        retryCount: retryCount,
      );

      if (_clientStatus == _ClientStatus.closed || status == Status.closed) {
        if (!_connectCompleter.isCompleted) {
          _connectCompleter.complete();
        }
        close();
        _clientStatus = _ClientStatus.closed;
        return;
      }
      if (!this._retry || retryCount != -1) {
        return _connectCompleter.future;
      }
      await for (var s in statusStream) {
        if (s == Status.disconnected) {
          break;
        }
        if (s == Status.closed) {
          return;
        }
      }
    } while (this._retry && retryCount == -1);
    return _connectCompleter.future;
  }

  void _connectLoop(Uri uri,
      {int timeout = 5,
      required int retryInterval,
      required int retryCount}) async {
    for (var count = 0;
        count == 0 || ((count < retryCount || retryCount == -1) && this._retry);
        count++) {
      if (count == 0) {
        _setStatus(Status.connecting);
      } else {
        _setStatus(Status.reconnecting);
      }

      try {
        if (_channelStream.isClosed) {
          _channelStream = StreamController();
        }
        var success = await _connectUri(uri, timeout: timeout);
        if (!success) {
          await Future.delayed(Duration(seconds: retryInterval));
          continue;
        }

        _buffer = [];

        return;
      } catch (err) {
        await close();
        if (!_connectCompleter.isCompleted) {
          _connectCompleter.completeError(err);
        }
        _setStatus(Status.disconnected);
      }
    }
    if (!_connectCompleter.isCompleted) {
      _clientStatus = _ClientStatus.closed;
      _connectCompleter
          .completeError(NatsException('can not connect ${uri.toString()}'));
    }
  }

  Future<bool> _connectUri(Uri uri, {int timeout = 5}) async {
    try {
      if (uri.scheme == '') {
        throw Exception(NatsException('No scheme in uri'));
      }
      switch (uri.scheme) {
        case 'wss':
        case 'ws':
          try {
            _wsChannel = WebSocketChannel.connect(uri);
          } catch (e) {
            return false;
          }
          if (_wsChannel == null) {
            return false;
          }
          _setStatus(Status.infoHandshake);
          _wsChannel?.stream.listen((event) {
            if (_channelStream.isClosed) return;
            _channelStream.add(event);
          }, onDone: () {
            _setStatus(Status.disconnected);
          }, onError: (e) {
            close();
            wsErrorHandler(e);
          });
          return true;
        case 'nats':
          var port = uri.port;
          if (port == 0) {
            port = 4222;
          }
          _tcpSocket = await Socket.connect(
            uri.host,
            port,
            timeout: Duration(seconds: timeout),
          );
          if (_tcpSocket == null) {
            return false;
          }
          _setStatus(Status.infoHandshake);
          _tcpSocket!.listen((event) {
            if (_secureSocket == null) {
              if (_channelStream.isClosed) return;
              _channelStream.add(event);
            }
          }).onDone(() {
            _setStatus(Status.disconnected);
          });
          return true;
        case 'tls':
          _tlsRequired = true;
          var port = uri.port;
          if (port == 0) {
            port = 4443;
          }
          _tcpSocket = await Socket.connect(uri.host, port,
              timeout: Duration(seconds: timeout));
          if (_tcpSocket == null) break;
          _setStatus(Status.infoHandshake);
          _tcpSocket!.listen((event) {
            if (_secureSocket == null) {
              if (_channelStream.isClosed) return;
              _channelStream.add(event);
            }
          });
          return true;
        default:
          throw Exception(
              NatsException('schema ${uri.scheme} is not supported'));
      }
    } catch (e) {
      return false;
    }
    return false;
  }

  void _backendSubscriptAll() {
    _backendSubs.clear();
    _subs.forEach((sid, s) async {
      _sub(s.subject, sid, queueGroup: s.queueGroup);
      // s.backendSubscription = true;
      _backendSubs[sid] = true;
    });
  }

  void _flushPubBuffer() {
    _pubBuffer.forEach((p) {
      _pub(p);
    });
  }

  void _processOp() async {
    ///find endline
    var nextLineIndex = _buffer.indexWhere((c) {
      if (c == 13) {
        return true;
      }
      return false;
    });
    if (nextLineIndex == -1) return;
    var line =
        String.fromCharCodes(_buffer.sublist(0, nextLineIndex)); // retest
    if (_buffer.length > nextLineIndex + 2) {
      _buffer.removeRange(0, nextLineIndex + 2);
    } else {
      _buffer = [];
    }

    ///decode operation
    var i = line.indexOf(' ');
    String op, data;
    if (i != -1) {
      op = line.substring(0, i).trim().toLowerCase();
      data = line.substring(i).trim();
    } else {
      op = line.trim().toLowerCase();
      data = '';
    }

    ///process operation
    switch (op) {
      case 'msg':
        _receiveState = _ReceiveState.msg;
        _receiveLine1 = line;
        _processMsg();
        _receiveLine1 = '';
        _receiveState = _ReceiveState.idle;
        break;
      case 'hmsg':
        _receiveState = _ReceiveState.msg;
        _receiveLine1 = line;
        _processHMsg();
        _receiveLine1 = '';
        _receiveState = _ReceiveState.idle;
        break;
      case 'info':
        _info = Info.fromJson(data);
        if (_tlsRequired && !(_info.tlsRequired ?? false)) {
          throw Exception(NatsException('require TLS but server not required'));
        }

        if ((_info.tlsRequired ?? false) && _tcpSocket != null) {
          _setStatus(Status.tlsHandshake);
          var secureSocket = await SecureSocket.secure(
            _tcpSocket!,
            context: this.securityContext,
            onBadCertificate: (certificate) {
              if (acceptBadCert) return true;
              return false;
            },
          );

          _secureSocket = secureSocket;
          secureSocket.listen((event) {
            if (_channelStream.isClosed) return;
            _channelStream.add(event);
          }, onError: (error) {
            print('Socket error: $error');
            _setStatus(Status.disconnected);

            if (error is TlsException) {
              this._retry = false;
              this.close();
              throw Exception(NatsException(error.message));
            }
          });
        }

        await _sign();
        _addConnectOption(_connectOption);
        if (_connectOption.verbose == true) {
          var ack = await _ackStream.stream.first;
          if (ack) {
            _setStatus(Status.connected);
          } else {
            _setStatus(Status.disconnected);
          }
        } else {
          _setStatus(Status.connected);
        }
        _backendSubscriptAll();
        _flushPubBuffer();
        if (!_connectCompleter.isCompleted) {
          _connectCompleter.complete();
        }
        break;
      case 'ping':
        if (status == Status.connected) {
          _add('pong');
        }
        break;
      case '-err':
        // _processErr(data);
        if (_connectOption.verbose == true) {
          _ackStream.sink.add(false);
        }
        break;
      case 'pong':
        _pingCompleter.complete();
        break;
      case '+ok':
        //do nothing
        if (_connectOption.verbose == true) {
          _ackStream.sink.add(true);
        }
        break;
    }
  }

  void _processMsg() {
    var s = _receiveLine1.split(' ');
    var subject = s[1];
    var sid = int.parse(s[2]);
    String? replyTo;
    int length;
    if (s.length == 4) {
      length = int.parse(s[3]);
    } else {
      replyTo = s[3];
      length = int.parse(s[4]);
    }
    if (_buffer.length < length) return;
    var payload = Uint8List.fromList(_buffer.sublist(0, length));
    // _buffer = _buffer.sublist(length + 2);
    if (_buffer.length > length + 2) {
      _buffer.removeRange(0, length + 2);
    } else {
      _buffer = [];
    }

    if (_subs[sid] != null) {
      _subs[sid]?.add(Message(subject, sid, payload, this, replyTo: replyTo));
    }
  }

  void _processHMsg() {
    var s = _receiveLine1.split(' ');
    var subject = s[1];
    var sid = int.parse(s[2]);
    String? replyTo;
    int length;
    int headerLength;
    if (s.length == 5) {
      headerLength = int.parse(s[3]);
      length = int.parse(s[4]);
    } else {
      replyTo = s[3];
      headerLength = int.parse(s[4]);
      length = int.parse(s[5]);
    }
    if (_buffer.length < length) return;
    var header = Uint8List.fromList(_buffer.sublist(0, headerLength));
    var payload = Uint8List.fromList(_buffer.sublist(headerLength, length));
    // _buffer = _buffer.sublist(length + 2);
    if (_buffer.length > length + 2) {
      _buffer.removeRange(0, length + 2);
    } else {
      _buffer = [];
    }

    if (_subs[sid] != null) {
      var msg = Message(subject, sid, payload, this,
          replyTo: replyTo, header: Header.fromBytes(header));
      _subs[sid]?.add(msg);
    }
  }

  /// Gets the maximum payload size supported by the server in bytes.
  ///
  /// This value is obtained from the server's INFO message during connection.
  /// Messages larger than this size will be rejected by the server.
  ///
  /// Example:
  /// ```dart
  /// final maxSize = client.maxPayload();
  /// if (data.length > maxSize!) {
  ///   throw Exception('Payload too large'); 
  /// }
  /// ```
  ///
  /// Returns:
  /// - The maximum payload size in bytes if connected to a server
  /// - null if not connected or server info not available
  ///
  /// See also:
  /// * [Info] - Contains server configuration including max payload
  /// * [pub] - Publishing method that uses this limit
  int? maxPayload() => _info.maxPayload;

  /// Sends a PING message to the NATS server and waits for a PONG response.
  ///
  /// Note: Currently does not implement PONG verification.
  ///
  /// Returns a [Future] that completes when the PONG is received.
  /// The future may complete with an error if the connection is lost.
  ///
  /// Example:
  /// ```dart
  /// try {
  ///   await client.ping();
  ///   print('Server responded');
  /// } catch (e) {
  ///   print('Server did not respond: $e');
  /// }
  /// ```
  Future ping() {
    _pingCompleter = Completer();
    _add('ping');
    return _pingCompleter.future;
  }

  void _addConnectOption(ConnectOption c) {
    _add('connect ' + c.toJson());
  }

  /// Whether to buffer publish operations when disconnected.
  ///
  /// When true (default), publish operations will be buffered if the client is not connected.
  /// The buffered messages will be sent once the connection is re-established.
  /// When false, publish operations will fail immediately if not connected.
  ///
  /// Example:
  /// ```dart
  /// client.defaultPubBuffer = false; // Disable buffering
  /// final success = await client.pubString('foo', 'message');
  /// // success will be false if not connected
  /// ```
  ///
  /// See also:
  /// * [pub] - Uses this setting when buffer parameter is not specified
  /// * [pubString] - String publishing method that uses this setting
  /// * [Status] - Connection status that affects buffering
  bool defaultPubBuffer = true;

  /// Publishes a binary message to the specified subject.
  ///
  /// Parameters:
  /// - [subject] The subject to publish to
  /// - [data] The binary message payload as a [Uint8List]
  /// - [replyTo] Optional reply subject for request-reply messaging
  /// - [buffer] Whether to buffer the message if disconnected (defaults to [defaultPubBuffer])
  /// - [header] Optional message headers
  ///
  /// Returns a [Future<bool>] that completes with:
  /// - `true` if the message was sent successfully or buffered
  /// - `false` if the client is disconnected and buffering is disabled
  ///
  /// Example:
  /// ```dart
  /// final data = Uint8List.fromList([1, 2, 3]);
  /// final success = await client.pub('foo', data);
  /// ```
  ///
  /// See also:
  /// * [pubString] - Convenience method for publishing string messages
  /// * [defaultPubBuffer] - Controls default buffering behavior
  /// * [Header] - For adding headers to messages
  Future<bool> pub(String? subject, Uint8List data,
      {String? replyTo, bool? buffer, Header? header}) async {
    buffer ??= defaultPubBuffer;
    if (status != Status.connected) {
      if (buffer) {
        _pubBuffer.add(_Pub(subject, data, replyTo));
        return true;
      } else {
        return false;
      }
    }

    String cmd;
    var headerByte = header?.toBytes();
    if (header == null) {
      cmd = 'pub';
    } else {
      cmd = 'hpub';
    }
    cmd += ' $subject';
    if (replyTo != null) {
      cmd += ' $replyTo';
    }
    if (headerByte != null) {
      cmd += ' ${headerByte.length}  ${headerByte.length + data.length}';
      _add(cmd);
      var dataWithHeader = headerByte.toList();
      dataWithHeader.addAll(data.toList());
      _addByte(dataWithHeader);
    } else {
      cmd += ' ${data.length}';
      _add(cmd);
      _addByte(data);
    }

    if (_connectOption.verbose == true) {
      var ack = await _ackStream.stream.first;
      return ack;
    }
    return true;
  }

  /// Publishes a string message to the specified subject.
  ///
  /// Convenience method that converts the string [str] to bytes and publishes it.
  /// Returns a Future that completes with true if the publish was successful.
  ///
  /// Parameters:
  /// - [subject] The subject to publish to
  /// - [str] The string message to publish
  /// - [replyTo] Optional reply subject for request-reply messaging
  /// - [buffer] Whether to buffer messages when disconnected (defaults to true)
  /// - [header] Optional message headers
  ///
  /// Example:
  /// ```dart
  /// final success = await client.pubString('foo', 'Hello NATS!');
  /// ```
  ///
  /// See also:
  /// * [pub] - Core publish method for raw byte data
  /// * [Header] - For adding headers to messages
  Future<bool> pubString(String subject, String str,
      {String? replyTo, bool buffer = true, Header? header}) async {
    return pub(subject, Uint8List.fromList(utf8.encode(str)),
        replyTo: replyTo, buffer: buffer);
  }

  Future<bool> _pub(_Pub p) async {
    if (p.replyTo == null) {
      _add('pub ${p.subject} ${p.data.length}');
    } else {
      _add('pub ${p.subject} ${p.replyTo} ${p.data.length}');
    }
    _addByte(p.data);
    if (_connectOption.verbose == true) {
      var ack = await _ackStream.stream.first;
      return ack;
    }
    return true;
  }

  T Function(String) _getJsonDecoder<T>() {
    var c = _jsonDecoder[T];
    if (c == null) {
      throw NatsException('no decoder for type $T');
    }
    return c as T Function(String);
  }

  // String Function(dynamic) _getJsonEncoder(Type T) {
  //   var c = _jsonDecoder[T];
  //   if (c == null) {
  //     throw NatsException('no encoder for type $T');
  //   }
  //   return c as String Function(dynamic);
  // }

  /// Subscribes to a NATS subject with optional queue group and JSON decoding.
  ///
  /// Creates a new subscription for receiving messages published to [subject].
  /// Returns a [Subscription] that provides a stream of messages.
  ///
  /// Parameters:
  /// - [subject] The subject to subscribe to
  /// - [queueGroup] Optional queue group for load balancing
  /// - [jsonDecoder] Optional custom JSON decoder function
  ///
  /// Example:
  /// ```dart
  /// // Basic subscription
  /// final sub = client.sub('foo');
  /// sub.stream.listen((msg) => print(msg.data));
  ///
  /// // With queue group
  /// final worker = client.sub('tasks', queueGroup: 'workers');
  /// ```
  ///
  /// See also:
  /// * [Subscription] - The subscription object returned
  /// * [unSub] - To unsubscribe when done
  Subscription<T> sub<T>(
    String subject, {
    String? queueGroup,
    T Function(String)? jsonDecoder,
  }) {
    _ssid++;

    //get registered json decoder
    if (T != dynamic && jsonDecoder == null) {
      jsonDecoder = _getJsonDecoder();
    }

    var s = Subscription<T>(_ssid, subject, this,
        queueGroup: queueGroup, jsonDecoder: jsonDecoder);
    _subs[_ssid] = s;
    if (status == Status.connected) {
      _sub(subject, _ssid, queueGroup: queueGroup);
      _backendSubs[_ssid] = true;
    }
    return s;
  }

  void _sub(String? subject, int sid, {String? queueGroup}) {
    if (queueGroup == null) {
      _add('sub $subject $sid');
    } else {
      _add('sub $subject $queueGroup $sid');
    }
  }

  /// Unsubscribes from a subscription to stop receiving messages.
  ///
  /// Parameters:
  /// - [s] The [Subscription] object to unsubscribe from
  ///
  /// Returns `true` if successfully unsubscribed, `false` if subscription not found.
  ///
  /// Example:
  /// ```dart
  /// final sub = client.sub('foo');
  /// // ... later when done
  /// client.unSub(sub);
  /// ```
  ///
  /// See also:
  /// * [sub] - To create subscriptions
  /// * [unSubById] - To unsubscribe using subscription ID
  bool unSub(Subscription s) {
    var sid = s.sid;

    if (_subs[sid] == null) return false;
    _unSub(sid);
    _subs.remove(sid);
    s.close();
    _backendSubs.remove(sid);
    return true;
  }

  /// Unsubscribes from a subscription using its ID number.
  ///
  /// Parameters:
  /// - [sid] The subscription ID to unsubscribe from
  ///
  /// Returns `true` if successfully unsubscribed, `false` if subscription not found.
  ///
  /// Example:
  /// ```dart
  /// final sub = client.sub('foo');
  /// client.unSubById(sub.sid);
  /// ```
  ///
  /// See also:
  /// * [unSub] - To unsubscribe using Subscription object
  /// * [sub] - To create subscriptions
  bool unSubById(int sid) {
    if (_subs[sid] == null) return false;
    return unSub(_subs[sid]!);
  }

  //todo unsub with max msgs

  void _unSub(int sid, {String? maxMsgs}) {
    if (maxMsgs == null) {
      _add('unsub $sid');
    } else {
      _add('unsub $sid $maxMsgs');
    }
  }

  void _add(String str) {
    if (status == Status.closed || status == Status.disconnected) {
      return;
    }
    if (_wsChannel != null) {
      // if (_wsChannel?.closeCode == null) return;
      _wsChannel?.sink.add(utf8.encode(str + '\r\n'));
      return;
    } else if (_secureSocket != null) {
      _secureSocket!.add(utf8.encode(str + '\r\n'));
      return;
    } else if (_tcpSocket != null) {
      _tcpSocket!.add(utf8.encode(str + '\r\n'));
      return;
    }
    throw Exception(NatsException('no connection'));
  }

  void _addByte(List<int> msg) {
    if (_wsChannel != null) {
      _wsChannel?.sink.add(msg);
      _wsChannel?.sink.add(utf8.encode('\r\n'));
      return;
    } else if (_secureSocket != null) {
      _secureSocket?.add(msg);
      _secureSocket?.add(utf8.encode('\r\n'));
      return;
    } else if (_tcpSocket != null) {
      _tcpSocket?.add(msg);
      _tcpSocket?.add(utf8.encode('\r\n'));
      return;
    }
    throw Exception(NatsException('no connection'));
  }

  var _inboxPrefix = '_INBOX';

  /// The inbox prefix used for generating unique inbox subjects.
  ///
  /// This prefix is used when creating inbox subjects for request-reply messaging.
  /// The default prefix is '_INBOX'. It can only be changed before the client is used.
  ///
  /// Example:
  /// ```dart
  /// client.inboxPrefix = 'MYAPP.INBOX'; // Must be set before connecting
  /// ```
  /// 
  /// See also:
  /// * [request] - Uses inbox subjects for request-reply messaging
  /// * [requestString] - String-based request-reply messaging
  String get inboxPrefix => _inboxPrefix;
  set inboxPrefix(String i) {
    if (_clientStatus == _ClientStatus.used) {
      throw NatsException('inbox prefix can not change when connection in use');
    }
    _inboxPrefix = i;
    _inboxSubPrefix = null;
  }

  final _inboxs = <String, Subscription>{};
  final _mutex = Mutex();
  String? _inboxSubPrefix;
  Subscription? _inboxSub;

  /// Sends a request to the specified subject and returns the response message.
  ///
  /// The [subj] parameter specifies the subject to send the request to.
  /// The [data] parameter contains the request payload as a [Uint8List].
  /// 
  /// Optional parameters:
  /// - [timeout] - Duration to wait for response before throwing TimeoutException (default: 2 seconds)
  /// - [jsonDecoder] - Custom JSON decoder function for parsing response data
  ///
  /// Returns a [Message<T>] containing the response.
  /// 
  /// Throws:
  /// - [TimeoutException] if no response received within timeout duration
  /// - [NatsException] if client is not connected
  ///
  /// Example:
  /// ```dart
  /// try {
  ///   final response = await client.request<String>(
  ///     'service',
  ///     Uint8List.fromList('request'.codeUnits),
  ///     timeout: Duration(seconds: 2)
  ///   );
  ///   print('Got response: ${response.data}');
  /// } on TimeoutException {
  ///   print('Request timed out');
  /// }
  /// ```
  /// 
  /// See also:
  /// * [requestString] - Convenience method for string requests
  /// * [requestJson] - Convenience method for JSON requests
  /// * [Message] - Response message type
  Future<Message<T>> request<T>(
    String subj,
    Uint8List data, {
    Duration timeout = const Duration(seconds: 2),
    T Function(String)? jsonDecoder,
  }) async {
    if (!connected) {
      throw NatsException("request error: client not connected");
    }
    Message resp;
    //ensure no other request
    await _mutex.acquire();
    //get registered json decoder
    if (T != dynamic && jsonDecoder == null) {
      jsonDecoder = _getJsonDecoder();
    }

    if (_inboxSubPrefix == null) {
      if (inboxPrefix == '_INBOX') {
        _inboxSubPrefix = inboxPrefix + '.' + Nuid().next();
      } else {
        _inboxSubPrefix = inboxPrefix;
      }
      _inboxSub = sub<T>(_inboxSubPrefix! + '.>', jsonDecoder: jsonDecoder);
    }
    var inbox = _inboxSubPrefix! + '.' + Nuid().next();
    var stream = _inboxSub!.stream;

    pub(subj, data, replyTo: inbox);

    try {
      do {
        resp = await stream.take(1).single.timeout(timeout);
      } while (resp.subject != inbox);
    } on TimeoutException {
      throw TimeoutException('request time > $timeout');
    } finally {
      _mutex.release();
    }
    var msg = Message<T>(
      resp.subject,
      resp.sid,
      resp.byte,
      this,
      header: resp.header,
      jsonDecoder: jsonDecoder,
    );
    return msg;
  }

  /// Sends a string request to a NATS subject and waits for a response.
  ///
  /// A convenience wrapper around [request] that accepts a string payload.
  ///
  /// Parameters:
  /// - [subj] The subject to publish the request to
  /// - [data] The string data to send in the request
  /// - [timeout] How long to wait for a response before throwing TimeoutException (default 2s)
  /// - [jsonDecoder] Optional function to decode JSON response data to type T
  ///
  /// Returns a [Message<T>] containing the response.
  ///
  /// Throws [TimeoutException] if no response is received within the timeout duration.
  /// Throws [NatsException] if the client is not connected.
  Future<Message<T>> requestString<T>(
    String subj,
    String data, {
    Duration timeout = const Duration(seconds: 2),
    T Function(String)? jsonDecoder,
  }) {
    return request<T>(
      subj,
      Uint8List.fromList(data.codeUnits),
      timeout: timeout,
      jsonDecoder: jsonDecoder,
    );
  }

  void _setStatus(Status newStatus) {
    _status = newStatus;
    _statusController.add(newStatus);
  }

  /// Closes the connection to the NATS server and cancels all future reconnection attempts.
  ///
  /// This is a more forceful version of [close] that ensures no automatic reconnection
  /// will be attempted after closing. It:
  /// - Sets the retry flag to false to prevent reconnection attempts
  /// - Calls [close] to cleanly shutdown the connection
  ///
  /// Use this when you want to permanently close the connection without possibility
  /// of automatic reconnection.
  Future forceClose() async {
    this._retry = false;
    this.close();
  }

  /// Closes the connection to the NATS server.
  ///
  /// This method:
  /// - Sets the client status to closed
  /// - Unsubscribes from all server-side subscriptions
  /// - Clears inbox mappings
  /// - Closes all socket connections (WebSocket, TCP, TLS)
  /// - Cleans up internal state
  ///
  /// Note: This preserves the client-side subscription list, allowing reconnection
  /// to restore subscriptions if [retry] is true.
  ///
  /// See also:
  /// - [forceClose] for permanently closing without reconnection possibility
  /// - [tcpClose] for testing-only connection closure
  Future close() async {
    _setStatus(Status.closed);
    _backendSubs.forEach((_, s) => s = false);
    _inboxs.clear();
    await _wsChannel?.sink.close();
    _wsChannel = null;
    await _secureSocket?.close();
    _secureSocket = null;
    await _tcpSocket?.close();
    _tcpSocket = null;
    await _inboxSub?.close();
    _inboxSub = null;
    _inboxSubPrefix = null;
    _buffer = [];
    _clientStatus = _ClientStatus.closed;
  }

  /// Establishes a TCP connection to a NATS server (Deprecated).
  ///
  /// This method is deprecated in favor of using [connect] with a URI.
  /// It exists for backward compatibility with version 0.2.x.
  ///
  /// Example:
  /// ```dart
  /// // Old way (deprecated):
  /// await client.tcpConnect('localhost', port: 4222);
  /// 
  /// // New way:
  /// await client.connect(Uri.parse('nats://localhost:4222'));
  /// ```
  ///
  /// @deprecated Use [connect] with a URI instead
  @Deprecated('use connect(uri) instead')
  Future tcpConnect(String host,
      {int port = 4222,
      ConnectOption? connectOption,
      int timeout = 5,
      bool retry = true,
      int retryInterval = 10}) {
    return connect(
      Uri(scheme: 'nats', host: host, port: port),
      retry: retry,
      retryInterval: retryInterval,
      timeout: timeout,
      connectOption: connectOption,
    );
  }

  /// Closes the TCP connection for testing purposes only.
  ///
  /// This method should only be used in test scenarios where you need to simulate
  /// a connection closure. For normal application shutdown, use [close] instead.
  ///
  /// The connection will be marked as disconnected after closing.
  Future<void> tcpClose() async {
    await _tcpSocket?.close();
    _setStatus(Status.disconnected);
  }

  /// Waits until the client establishes a connection to the NATS server.
  ///
  /// This method blocks until the client's status changes to [Status.connected].
  /// It's useful when you need to ensure the client is connected before proceeding
  /// with operations.
  ///
  /// Example:
  /// ```dart
  /// var client = Client();
  /// await client.connect(Uri.parse('nats://localhost:4222'));
  /// await client.waitUntilConnected();
  /// // Client is now connected and ready for operations
  /// ```
  ///
  /// See also:
  /// * [waitUntil] - Wait for a specific status
  /// * [status] - Get the current connection status
  Future<void> waitUntilConnected() async {
    await waitUntil(Status.connected);
  }

  /// Waits until the client reaches a specific connection status.
  ///
  /// This method blocks until the client's status matches the specified [s] status.
  /// It's useful when you need to wait for the client to reach a particular state
  /// before proceeding with operations.
  ///
  /// Parameters:
  /// * [s] - The target [Status] to wait for
  ///
  /// Example:
  /// ```dart
  /// var client = Client();
  /// await client.connect(Uri.parse('nats://localhost:4222'));
  /// await client.waitUntil(Status.connected);
  /// // Client has now reached the connected status
  /// ```
  ///
  /// See also:
  /// * [waitUntilConnected] - Convenience method to wait for connected status
  /// * [status] - Get the current connection status
  /// * [statusStream] - Stream of status changes
  Future<void> waitUntil(Status s) async {
    if (status == s) {
      return;
    }
    await for (var st in statusStream) {
      if (st == s) {
        break;
      }
    }
  }
}
