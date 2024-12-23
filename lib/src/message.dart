import 'dart:convert';
import 'dart:typed_data';

import 'client.dart';

/// A class representing NATS message headers that can contain metadata about messages.
///
/// Headers allow attaching key-value metadata to NATS messages. Each header has a version
/// and a map of string key-value pairs.
///
/// Example:
/// ```dart
/// final header = Header()
///   ..add('Content-Type', 'application/json')
///   ..add('Request-ID', '12345');
/// ```
///
/// See also:
/// * [Message] - The main message class that can contain these headers
/// * The NATS headers specification: https://docs.nats.io/reference/reference-protocols/nats-protocol#headers
class Header {
  /// The version string for the NATS header protocol.
  ///
  /// Typically follows the format 'NATS/x.y' where x.y is the version number.
  /// The default value is 'NATS/1.0' which is the current NATS header protocol version.
  ///
  /// Example:
  /// ```dart
  /// final header = Header(version: 'NATS/1.0');
  /// ```
  ///
  /// See also:
  /// * [Header.fromBytes] - Parses version from raw bytes
  /// * [Header.toBytes] - Serializes version to bytes
  /// * NATS protocol spec: https://docs.nats.io/reference/reference-protocols/nats-protocol#headers
  String version;

  /// A map containing the header key-value pairs.
  ///
  /// Each key and value is a string. The map stores metadata about the NATS message
  /// like content type, correlation IDs, etc.
  ///
  /// Example:
  /// ```dart
  /// final header = Header();
  /// header.headers = {
  ///   'Content-Type': 'application/json',
  ///   'Request-ID': '12345'
  /// };
  /// ```
  ///
  /// See also:
  /// * [add] - Helper method to add header key-value pairs
  /// * [get] - Helper method to retrieve header values
  /// * [toBytes] - Serializes headers to bytes
  Map<String, String>? headers;

  /// Creates a new [Header] instance with optional headers and version.
  ///
  /// Parameters:
  /// - [headers] - Optional map of string key-value header pairs. Defaults to null.
  /// - [version] - Optional header protocol version string. Defaults to 'NATS/1.0'.
  ///
  /// If [headers] is null, initializes an empty map. The [version] parameter should
  /// follow the format 'NATS/x.y' where x.y is the version number.
  ///
  /// Example:
  /// ```dart
  /// final header = Header(
  ///   headers: {'Content-Type': 'application/json'},
  ///   version: 'NATS/1.0'
  /// );
  /// ```
  ///
  /// See also:
  /// * [fromBytes] - Alternative constructor that parses from bytes
  /// * [add] - Helper method to add headers after construction
  Header({this.headers, this.version = 'NATS/1.0'}) {
    this.headers ??= {};
  }

  /// Adds a key-value pair to the headers map.
  ///
  /// Parameters:
  /// - [key] - The header key/name to add
  /// - [value] - The value to associate with the key
  ///
  /// Returns this [Header] instance for method chaining.
  ///
  /// Example:
  /// ```dart
  /// final header = Header()
  ///   ..add('Content-Type', 'application/json')
  ///   ..add('Request-ID', '12345');
  /// ```
  ///
  /// See also:
  /// * [get] - Retrieves a header value by key
  /// * [headers] - The underlying headers map
  Header add(String key, String value) {
    headers![key] = value;
    return this;
  }

  /// Gets a header value by key from the headers map.
  ///
  /// Parameters:
  /// - [key] - The header key/name to look up
  ///
  /// Returns the value associated with the key, or null if the key is not found.
  ///
  /// Example:
  /// ```dart
  /// final header = Header()..add('Content-Type', 'application/json');
  /// final contentType = header.get('Content-Type'); // Returns 'application/json'
  /// final missing = header.get('Missing-Key'); // Returns null
  /// ```
  ///
  /// See also:
  /// * [add] - Adds a new header key-value pair
  /// * [headers] - The underlying headers map
  String? get(String key) {
    return headers![key];
  }

  /// Creates a [Header] instance by parsing a byte array containing NATS headers.
  ///
  /// Parses a byte array containing NATS headers in the format:
  /// ```
  /// NATS/1.0\r\n
  /// Key1:Value1\r\n
  /// Key2:Value2\r\n
  /// ```
  /// 
  /// Parameters:
  /// - [b] The byte array containing the header data in UTF-8 encoding
  ///
  /// Returns a new [Header] instance containing the parsed version and headers.
  ///
  /// Example:
  /// ```dart
  /// final bytes = utf8.encode('NATS/1.0\r\nContent-Type:application/json\r\n');
  /// final header = Header.fromBytes(bytes);
  /// print(header.get('Content-Type')); // Prints: application/json
  /// ```
  ///
  /// See also:
  /// * [toBytes] - Converts headers back to bytes
  /// * [Header] - Main constructor for creating headers directly
  factory Header.fromBytes(Uint8List b) {
    var str = utf8.decode(b);
    Map<String, String> m = {};
    var strList = str.split('\r\n');
    strList.removeWhere((element) => element.isEmpty);
    var version = strList[0];
    strList.removeAt(0);
    for (var h in strList) {
      /// values of headers can contain ':' so find the first index for the
      /// correct split index
      var splitIndex = h.indexOf(':');

      /// if the index is <= to 0 it means there was either no ':' or its the
      /// first character. In either case its not a valid header to split.
      if (splitIndex <= 0) {
        continue;
      }
      var key = h.substring(0, splitIndex);
      var value = h.substring(splitIndex + 1);
      m[key] = value;
    }

    return Header(headers: m, version: version);
  }

  /// Converts this header to a UTF-8 encoded byte array.
  /// 
  /// The bytes follow the NATS header format:
  /// ```
  /// NATS/1.0\r\n
  /// Key1: Value1\r\n
  /// Key2: Value2\r\n
  /// ```
  /// 
  /// Example:
  /// ```dart
  /// final header = Header(headers: {'Content-Type': 'application/json'});
  /// final bytes = header.toBytes(); // Returns encoded bytes
  /// ```
  Uint8List toBytes() {
    var str = '${this.version}\r\n';

    headers?.forEach((k, v) {
      str = str + '$k:$v\r\n';
    });

    return Uint8List.fromList(utf8.encode(str + '\r\n'));
  }
}




/// A class representing a NATS message with typed payload data.
///
/// Messages contain the payload data along with metadata like subject, reply-to subject,
/// headers, and subscription ID. The payload can be accessed as raw bytes or converted
/// to a typed object using a JSON decoder.
///
/// Type parameter [T] defines the expected type of the decoded payload data.
///
/// Example:
/// ```dart
/// // String message
/// final msg = Message<String>('subject', 1, utf8.encode('hello'), client);
/// print(msg.string); // Prints: hello
///
/// // JSON message with custom type
/// final msg = Message<User>(
///   'users.created',
///   1,
///   jsonBytes,
///   client,
///   jsonDecoder: (json) => User.fromJson(jsonDecode(json))
/// );
/// final user = msg.data; // Decoded User object
/// ```
///
/// See also:
/// * [Header] - For working with NATS message headers
/// * [Client] - The NATS client that processes these messages
class Message<T> {
  ///subscriber id auto generate by client
  final int sid;

  /// The subject this message was published to
  final String? subject;

  /// The reply-to subject for request-reply messaging
  final String? replyTo;

  final Client _client;

  /// Optional headers containing metadata key-value pairs for this message
  final Header? header;

  /// Raw binary payload data as bytes
  final Uint8List byte;

  /// Optional function to decode JSON string payloads into type T
  T Function(String)? jsonDecoder;

  /// Returns the decoded message payload as type T, using [jsonDecoder] if provided
  T get data {
    // if (jsonDecoder == null) throw Exception('no converter. can not convert. use msg.byte instead');
    if (jsonDecoder == null) {
      return byte as T;
    }
    return jsonDecoder!(string);
  }

  /// Creates a new message with the given subject, subscriber ID, and payload.
  ///
  /// Parameters:
  /// - [subject] The subject this message was published to
  /// - [sid] The subscriber ID assigned by the client
  /// - [byte] The raw binary payload data
  /// - [_client] The NATS client that processes this message
  /// - [replyTo] Optional reply-to subject for request-reply messaging
  /// - [jsonDecoder] Optional function to decode JSON payloads into type T
  /// - [header] Optional headers containing metadata key-value pairs
  ///
  /// Example:
  /// ```dart
  /// final msg = Message<String>(
  ///   'foo.bar',
  ///   1,
  ///   utf8.encode('hello'),
  ///   client,
  ///   replyTo: 'response'
  /// );
  /// ```
  ///
  /// See also:
  /// * [data] - Gets the decoded payload using [jsonDecoder]
  /// * [string] - Gets the payload as a UTF-8 string
  /// * [respond] - Sends a response on the [replyTo] subject
  Message(this.subject, this.sid, this.byte, this._client,
      {this.replyTo, this.jsonDecoder, this.header});

  /// Returns the message payload decoded as a UTF-8 string
  String get string => utf8.decode(byte);

  /// Sends a response on this message's reply subject.
  ///
  /// Parameters:
  /// - [data] The binary response payload to send
  ///
  /// Returns:
  /// - `true` if the response was sent successfully
  /// - `false` if there is no reply subject to respond to
  ///
  /// Example:
  /// ```dart
  /// final response = Uint8List.fromList([1, 2, 3]);
  /// msg.respond(response);
  /// ```
  ///
  /// See also:
  /// * [respondString] - Convenience method for responding with strings
  /// * [replyTo] - The reply subject used for the response
  bool respond(Uint8List data) {
    if (replyTo == null || replyTo == '') return false;
    _client.pub(replyTo, data);
    return true;
  }

  /// Sends a string response on this message's reply subject.
  ///
  /// Parameters:
  /// - [str] The string response to send, which will be UTF-8 encoded
  ///
  /// Returns:
  /// - `true` if the response was sent successfully
  /// - `false` if there is no reply subject to respond to
  ///
  /// Example:
  /// ```dart
  /// msg.respondString('Hello back!');
  /// ```
  ///
  /// See also:
  /// * [respond] - For sending binary responses
  /// * [replyTo] - The reply subject used for the response
  bool respondString(String str) {
    return respond(Uint8List.fromList(utf8.encode(str)));
  }
}
