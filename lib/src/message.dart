///message model sending from NATS server
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

    return Uint8List.fromList(utf8.encode(str));
  }
}

/// Message class
class Message<T> {
  ///subscriber id auto generate by client
  final int sid;

  /// subject  and replyto
  final String? subject, replyTo;
  final Client _client;

  /// message header
  final Header? header;

  ///payload of data in byte
  final Uint8List byte;

  ///convert from json string to T for structure data
  T Function(String)? jsonDecoder;

  ///payload of data in byte
  T get data {
    // if (jsonDecoder == null) throw Exception('no converter. can not convert. use msg.byte instead');
    if (jsonDecoder == null) {
      return byte as T;
    }
    return jsonDecoder!(string);
  }

  ///constructor
  Message(this.subject, this.sid, this.byte, this._client,
      {this.replyTo, this.jsonDecoder, this.header});

  ///payload in string
  String get string => utf8.decode(byte);

  ///Respond to message
  bool respond(Uint8List data) {
    if (replyTo == null || replyTo == '') return false;
    _client.pub(replyTo, data);
    return true;
  }

  ///Respond to string message
  bool respondString(String str) {
    return respond(Uint8List.fromList(utf8.encode(str)));
  }
}
