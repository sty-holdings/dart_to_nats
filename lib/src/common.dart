import 'dart:convert';

extension _AddIfNotNull on Map<String, Object> {
  /// Conditionally adds a key-value pair to the map if the value is not null.
  ///
  /// Takes a [String] [key] and an [Object?] [value]. If [value] is not null,
  /// adds the key-value pair to the map. If [value] is null, the map remains unchanged.
  ///
  /// This is useful for building maps where some values may be optional:
  ///
  /// ```dart
  /// final map = <String, Object>{};
  /// map.addIfNotNull('name', 'John');     // Adds {'name': 'John'}
  /// map.addIfNotNull('age', null);        // Map unchanged
  /// map.addIfNotNull('active', true);     // Adds {'active': true}
  /// ```
  ///
  /// The value must be convertible to [Object] if not null.
  /// The original map is modified in place.
  void addIfNotNull(String key, Object? value) {
    if (value != null) {
      this[key] = value;
    }
  }
}

/// Extracts and casts a field to the specified type T.
///
/// Attempts to cast the given [field] to type T. If the cast fails,
/// throws a [NatsException] with details about the failed cast.
///
/// Parameters:
/// - [field] The object to be cast to type T
///
/// Returns:
/// The [field] cast to type T
///
/// Throws:
/// - [NatsException] if the cast operation fails
///
/// Example:
/// ```dart
/// String name = _extract<String>(jsonData['name']);
/// int age = _extract<int>(jsonData['age']);
/// ```
T _extract<T>(Object? field) {
  try {
    return field as T;
  } catch (e) {
    throw NatsException('field $field is not of type $T');
  }
}

/// Represents information about a NATS server received during connection.
///
/// Contains details about the server's configuration, version, and capabilities
/// that are exchanged during the initial connection handshake.
///
/// Example:
/// ```dart
/// final info = Info();
/// print(info.serverId); // Server's unique identifier
/// print(info.version);  // Server version
/// ```
///
/// See also:
/// * [Client] - Uses this info during connection setup
/// * [Status.infoHandshake] - Status during info exchange
class Info {
  /// Unique identifier of the NATS server
  String serverId;

  /// Name assigned to the NATS server
  String serverName;

  /// Version string of the NATS server software
  String version;

  /// Version of the Go runtime used by the NATS server
  String go;

  /// Hostname or IP address where the NATS server is listening
  String host;

  /// TCP port number where the NATS server accepts client connections
  int port;

  /// Whether the server supports headers in messages
  bool headers;

  /// Maximum allowed size of message payloads in bytes
  int maxPayload;

  /// Protocol version number supported by the server
  int proto;

  /// Unique identifier assigned to this client by the server
  int? clientId;

  /// Whether the server requires authentication
  bool? authRequired;

  /// Whether TLS encryption is required for client connections
  bool? tlsRequired;

  /// Whether the server verifies TLS certificates
  bool? tlsVerify;

  /// Whether TLS encryption is available on this server
  bool? tlsAvailable;

  /// List of alternative server URLs that clients can connect to
  List<String>? connectUrls;

  /// List of WebSocket URLs that clients can use to connect
  List<String>? wsConnectUrls;

  /// Whether Limited Delivery Mode is enabled
  bool? ldm;

  /// Git commit hash of the server build
  String? gitCommit;

  /// Whether JetStream is enabled on this server
  bool? jetstream;

  /// Server's detected IP address
  String? ip;

  /// Connecting client's IP address
  String? clientIp;

  /// Authentication nonce provided by the server
  String? nonce;

  /// Name of the cluster this server belongs to
  String? cluster;

  /// Domain name this server belongs to
  String? domain;

  /// Creates a new [Info] instance with server information.
  ///
  /// Required parameters:
  /// - [serverId] - Unique identifier of the NATS server
  /// - [serverName] - Name assigned to the NATS server
  /// - [version] - Version string of the NATS server software
  /// - [go] - Version of the Go runtime used by the server
  /// - [host] - Hostname or IP address where server is listening
  /// - [port] - TCP port number for client connections
  /// - [headers] - Whether the server supports headers
  /// - [maxPayload] - Maximum allowed message payload size
  /// - [proto] - Protocol version number supported
  ///
  /// Optional parameters:
  /// - [clientId] - Unique identifier assigned to this client
  /// - [authRequired] - Whether authentication is required
  /// - [tlsRequired] - Whether TLS encryption is required
  /// - [tlsVerify] - Whether TLS certificates are verified
  /// - [tlsAvailable] - Whether TLS encryption is available
  /// - [connectUrls] - Alternative server URLs for connections
  /// - [wsConnectUrls] - WebSocket URLs for connections
  /// - [ldm] - Whether Limited Delivery Mode is enabled
  /// - [gitCommit] - Git commit hash of the server build
  /// - [jetstream] - Whether JetStream is enabled
  /// - [ip] - Server's detected IP address
  /// - [clientIp] - Connecting client's IP address
  /// - [nonce] - Authentication nonce from server
  /// - [cluster] - Name of the server's cluster
  /// - [domain] - Domain name of the server
  Info(
      {required this.serverId,
      required this.serverName,
      required this.version,
      required this.go,
      required this.host,
      required this.port,
      required this.headers,
      required this.maxPayload,
      required this.proto,
      this.clientId,
      this.authRequired,
      this.tlsRequired,
      this.tlsVerify,
      this.tlsAvailable,
      this.connectUrls,
      this.wsConnectUrls,
      this.ldm,
      this.gitCommit,
      this.jetstream,
      this.ip,
      this.clientIp,
      this.nonce,
      this.cluster,
      this.domain});

  /// Creates an [Info] instance from a JSON map.
  ///
  /// Parses a JSON string containing NATS server information and creates a new [Info] instance.
  /// The JSON must contain required fields like server_id, server_name, version, etc.
  /// Optional fields will be parsed if present.
  ///
  /// Parameters:
  /// - [json] A JSON string containing the server information
  ///
  /// Returns:
  /// An [Info] instance populated with the server information from the JSON
  ///
  /// Throws:
  /// - [FormatException] if the JSON string is invalid
  /// - [NatsException] if required fields are missing or of wrong type
  ///
  /// Example:
  /// ```dart
  /// final jsonStr = '{"server_id": "abc123", "server_name": "my-server", ...}';
  /// final info = Info.fromJson(jsonStr);
  /// ```
  ///
  /// The JSON map should contain the following fields:
  /// - server_id: Unique server identifier (required)
  /// - server_name: Name of the NATS server (required)
  /// - version: Server version string (required)
  /// - proto: Protocol version number (required)
  /// - go: Go runtime version (required)
  /// - host: Server hostname (required)
  /// - port: Server port number (required)
  /// - headers: Whether headers are supported (required)
  /// - max_payload: Maximum allowed payload size (required)
  /// - client_id: Client identifier assigned by server (optional)
  /// - auth_required: Whether authentication is required (optional)
  /// - tls_required: Whether TLS is required (optional)
  /// - nonce: Server nonce for authentication (optional)
  factory Info.fromJson(String json) {
    final data = jsonDecode(json);
    final serverId = _extract<String>(data['server_id']);
    final serverName = _extract<String>(data['server_name']);
    final version = _extract<String>(data['version']);
    final go = _extract<String>(data['go']);
    final host = _extract<String>(data['host']);
    final port = _extract<int>(data['port']);
    final headers = _extract<bool>(data['headers']);
    final maxPayload = _extract<int>(data['max_payload']);
    final proto = _extract<int>(data['proto']);
    final clientId = _extract<int?>(data['client_id']);
    final authRequired = _extract<bool?>(data['auth_required']);
    final tlsRequired = _extract<bool?>(data['tls_required']);
    final tlsVerify = _extract<bool?>(data['tls_verify']);
    final tlsAvailable = _extract<bool?>(data['tls_available']);
    // connectUrls = _extract<List<String>?>(data['connect_urls']);
    // wsConnectUrls = _extract<List<String>?>(data['ws_connect_urls']);
    final ldm = _extract<bool?>(data['ldm']);
    final gitCommit = _extract<String?>(data['git_commit']);
    final jetstream = _extract<bool?>(data['jetstream']);
    final ip = _extract<String?>(data['ip']);
    final clientIp = _extract<String?>(data['client_ip']);
    final nonce = _extract<String?>(data['nonce']);
    final cluster = _extract<String?>(data['cluster']);
    final domain = _extract<String?>(data['domain']);

    return Info(
        serverId: serverId,
        serverName: serverName,
        version: version,
        go: go,
        host: host,
        port: port,
        headers: headers,
        maxPayload: maxPayload,
        proto: proto,
        clientId: clientId,
        authRequired: authRequired,
        tlsRequired: tlsRequired,
        tlsVerify: tlsVerify,
        tlsAvailable: tlsAvailable,
        // connectUrls: connectUrls,
        // wsConnectUrls: wsConnectUrls,
        ldm: ldm,
        gitCommit: gitCommit,
        jetstream: jetstream,
        ip: ip,
        clientIp: clientIp,
        nonce: nonce,
        cluster: cluster,
        domain: domain);
  }

  /// Converts this [Info] instance to a JSON string.
  ///
  /// Creates a JSON representation of the server information by encoding all non-null fields.
  /// The resulting JSON string contains key-value pairs for server details like:
  /// - server_id: Unique server identifier
  /// - server_name: Name of the NATS server
  /// - version: Server version string
  /// - proto: Protocol version number
  /// - go: Go runtime version
  /// - host: Server hostname
  /// - port: Server port number
  /// - headers: Whether headers are supported
  /// - max_payload: Maximum allowed payload size
  /// - client_id: Client identifier assigned by server
  /// - auth_required: Whether authentication is required
  /// - tls_required: Whether TLS is required
  /// - tls_verify: Whether TLS certificate verification is required
  /// - tls_available: Whether TLS is available
  /// - ldm: Whether LDM is enabled
  /// - git_commit: Git commit hash of server build
  /// - jetstream: Whether JetStream is enabled
  /// - ip: Server IP address
  /// - client_ip: Client IP address
  /// - nonce: Server nonce for authentication
  /// - cluster: Name of server cluster
  /// - domain: Server domain name
  ///
  /// Returns:
  /// A JSON string containing all non-null fields from this [Info] instance.
  ///
  /// Example:
  /// ```dart
  /// final info = Info(...);
  /// final json = info.toJson();
  /// print(json); // {"server_id": "abc123", "version": "2.0.0", ...}
  /// ```
  String toJson() {
    final data = <String, Object>{};
    data.addIfNotNull('server_id', serverId);
    data.addIfNotNull('server_name', serverName);
    data.addIfNotNull('version', version);
    data.addIfNotNull('go', go);
    data.addIfNotNull('host', host);
    data.addIfNotNull('port', port);
    data.addIfNotNull('headers', headers);
    data.addIfNotNull('max_payload', maxPayload);
    data.addIfNotNull('proto', proto);
    data.addIfNotNull('client_id', clientId);
    data.addIfNotNull('auth_required', authRequired);
    data.addIfNotNull('tls_required', tlsRequired);
    data.addIfNotNull('tls_verify', tlsVerify);
    data.addIfNotNull('tls_available', tlsAvailable);
    data.addIfNotNull('ldm', ldm);
    data.addIfNotNull('git_commit', gitCommit);
    data.addIfNotNull('jetstream', jetstream);
    data.addIfNotNull('ip', ip);
    data.addIfNotNull('client_ip', clientIp);
    data.addIfNotNull('nonce', nonce);
    data.addIfNotNull('cluster', cluster);
    data.addIfNotNull('domain', domain);

    return jsonEncode(data);
  }
}

/// Configuration options for connecting to a NATS server.
///
/// Contains authentication and connection settings that are sent to the server
/// during the initial connection handshake. These options configure how the client
/// authenticates and interacts with the server.
///
/// The options include:
/// - Authentication via username/password, token, JWT, or NKEY
/// - TLS configuration
/// - Protocol settings like verbose mode and headers support
/// - Client identification and metadata
///
/// Example:
/// ```dart
/// final options = ConnectOption()
///   ..user = 'myuser'
///   ..pass = 'password'
///   ..name = 'my-client'
///   ..headers = true;
/// ```
///
/// The options are sent to the server as part of the CONNECT protocol message
/// when establishing a connection.
///
/// See also:
/// * [Client] - Uses these options when connecting to a server
/// * [Info] - Server information received in response to connect
/// * [NatsException] - Thrown if connection fails due to invalid options
class ConnectOption {
  /// Whether server sends +OK responses (defaults to true, auto-disabled after connect)
  bool verbose;

  /// Whether server performs additional protocol compliance checks (defaults to false)
  bool pedantic;

  /// Whether client requires TLS for the connection (not implemented yet)
  bool tlsRequired = false;

  /// Authentication token for connecting to the server
  String? authToken;

  /// Username for basic authentication
  String? user;

  /// Password for basic authentication
  String? pass;

  /// Client name
  String? name;

  /// Client language identifier (defaults to 'dart')
  String? lang;

  /// Client version identifier (defaults to '0.1.0')
  String? version;

  /// NATS protocol version (defaults to 1)
  int? protocol;

  /// Whether server should echo messages back to sender (defaults to false)
  bool? echo;

  /// signature jwt.sig = sign(hash(jwt.header + jwt.body), private-key(jwt.issuer))(jwt.issuer is part of jwt.body)
  String? sig;

  /// JWT token used for authentication with the NATS server
  String? jwt;

  /// Whether server should send an error response when no responders are available for a request (defaults to false)
  bool? noResponders;

  /// Whether server should support message headers (defaults to true)
  bool? headers;

  /// NKey for authentication with the NATS server
  String? nkey;

  /// Creates a new [ConnectOption] instance with the specified connection parameters.
  ///
  /// Parameters:
  /// - [verbose] Whether server sends +OK responses (defaults to false)
  /// - [pedantic] Whether server performs additional protocol compliance checks (defaults to false)
  /// - [authToken] Authentication token for connecting to the server
  /// - [jwt] JWT token used for authentication
  /// - [nkey] NKey for authentication
  /// - [user] Username for basic authentication
  /// - [pass] Password for basic authentication
  /// - [tlsRequired] Whether TLS is required for the connection (defaults to false)
  /// - [name] Client name identifier
  /// - [lang] Client language identifier (defaults to 'dart')
  /// - [version] Client version identifier (defaults to '0.1.0')
  /// - [headers] Whether server should support message headers (defaults to true)
  /// - [protocol] NATS protocol version (defaults to 1)
  /// - [echo] Whether server should echo messages back to sender (defaults to false)
  /// - [noResponders] Whether server should send error when no responders exist
  /// - [sig] Signature for JWT authentication
  ///
  /// Example:
  /// ```dart
  /// final options = ConnectOption(
  ///   name: 'my-client',
  ///   user: 'admin',
  ///   pass: 'secret',
  ///   headers: true
  /// );
  /// ```
  ///
  /// See also:
  /// * [fromJson] - Creates options from JSON
  /// * [toJson] - Converts options to JSON
  ConnectOption(
      {this.verbose = false,
      this.pedantic = false,
      this.authToken,
      this.jwt,
      this.nkey,
      this.user,
      this.pass,
      this.tlsRequired = false,
      this.name,
      this.lang = 'dart',
      this.version = '0.1.0',
      this.headers = true,
      this.protocol = 1,
      this.echo = false,
      this.noResponders,
      this.sig});

  /// Creates a [ConnectOption] instance by parsing the provided JSON string.
  ///
  /// The JSON string should contain connection options as key-value pairs. All fields
  /// are optional and will use default values if not specified.
  ///
  /// Example JSON format:
  /// ```json
  /// {
  ///   "verbose": false,      // Enable verbose mode
  ///   "pedantic": false,     // Enable strict checking
  ///   "tls_required": true,  // Require TLS connection
  ///   "auth_token": "123",   // Authentication token
  ///   "user": "admin",       // Username for auth
  ///   "pass": "secret",      // Password for auth
  ///   "name": "client1"      // Client identifier
  /// }
  /// ```
  ///
  /// The following fields are supported:
  /// - `verbose`: Whether server sends +OK responses
  /// - `pedantic`: Whether server performs additional protocol compliance checks
  /// - `tls_required`: Whether TLS is required for the connection
  /// - `auth_token`: Authentication token for connecting to the server
  /// - `jwt`: JWT token used for authentication
  /// - `nkey`: NKey for authentication
  /// - `sig`: Signature for JWT authentication
  /// - `user`: Username for basic authentication
  /// - `pass`: Password for basic authentication
  /// - `name`: Client name identifier
  /// - `lang`: Client language identifier (defaults to 'dart')
  /// - `version`: Client version identifier
  /// - `headers`: Whether server should support message headers
  /// - `protocol`: NATS protocol version
  /// - `no_responders`: Whether server should send error when no responders exist
  /// - `echo`: Whether server should echo messages back to sender
  ///
  /// {@template connect_option_from_json}
  /// Throws a [FormatException] if the JSON string is invalid or cannot be decoded.
  /// Throws a [NatsException] if any field values don't match their expected types.
  /// {@endtemplate}
  ///
  /// See also:
  /// * [toJson] for converting a [ConnectOption] back to JSON
  /// * The default constructor for creating options directly
  factory ConnectOption.fromJson(String json) {
    final data = jsonDecode(json);
    final verbose = _extract<bool>(data['verbose']);
    final pedantic = _extract<bool>(data['pedantic']);
    final tlsRequired = _extract<bool>(data['tls_required']);
    final authToken = _extract<String?>(data['auth_token']);
    final jwt = _extract<String?>(data['jwt']);
    final nkey = _extract<String?>(data['nkey']);
    final sig = _extract<String?>(data['sig']);
    final user = _extract<String?>(data['user']);
    final pass = _extract<String?>(data['pass']);
    final name = _extract<String?>(data['name']);
    final lang = _extract<String>(data['lang']);
    final version = _extract<String?>(data['version']);
    final headers = _extract<bool?>(data['headers']);
    final protocol = _extract<int?>(data['protocol']);
    final noResponders = _extract<bool?>(data['no_responders']);
    final echo = _extract<bool?>(data['echo']);

    return ConnectOption(
        verbose: verbose,
        pedantic: pedantic,
        tlsRequired: tlsRequired,
        authToken: authToken,
        jwt: jwt,
        nkey: nkey,
        sig: sig,
        user: user,
        pass: pass,
        name: name,
        lang: lang,
        version: version,
        headers: headers,
        protocol: protocol,
        noResponders: noResponders,
        echo: echo);
  }

  /// Converts the [ConnectOption] instance to a JSON string representation.
  ///
  /// Creates a map of all non-null fields and encodes it to JSON format.
  /// Fields with null values are omitted from the output.
  ///
  /// Returns:
  /// A JSON string containing all non-null fields of this [ConnectOption].
  ///
  /// Example:
  /// ```dart
  /// final options = ConnectOption(verbose: true, name: 'client1');
  /// print(options.toJson()); // {"verbose":true,"name":"client1"}
  /// ```
  ///
  /// See also:
  /// * [ConnectOption.fromJson] for parsing a JSON string back to a [ConnectOption]
  String toJson() {
    final data = <String, Object>{};
    data.addIfNotNull('verbose', verbose);
    data.addIfNotNull('pedantic', pedantic);
    data.addIfNotNull('tls_required', tlsRequired);
    data.addIfNotNull('auth_token', authToken);
    data.addIfNotNull('jwt', jwt);
    data.addIfNotNull('nkey', nkey);
    data.addIfNotNull('sig', sig);
    data.addIfNotNull('user', user);
    data.addIfNotNull('pass', pass);
    data.addIfNotNull('name', name);
    data.addIfNotNull('lang', lang);
    data.addIfNotNull('version', version);
    data.addIfNotNull('headers', headers);
    data.addIfNotNull('protocol', protocol);
    data.addIfNotNull('no_responders', noResponders);
    data.addIfNotNull('echo', echo);

    return jsonEncode(data);
  }
}

/// A custom exception class for NATS-related errors.
///
/// This exception is thrown when operations related to NATS messaging
/// encounter errors, such as connection failures, protocol violations,
/// or invalid message formats.
///
/// Example:
/// ```dart
/// throw NatsException('Failed to connect to NATS server');
/// ```
///
/// See also:
/// * [NkeysException] - For NKEY-specific errors
class NatsException implements Exception {
  /// The error message describing what went wrong.
  final String? message;

  /// NatsException
  NatsException(this.message);

  /// Creates a new [NatsException] with an optional error [message].
  ///
  /// The [message] parameter provides details about what caused the exception.
  /// If omitted, a generic exception without a specific message is created.
  ///
  /// Example:
  /// ```dart
  /// throw NatsException('Connection timeout after 30 seconds');
  /// ```
  @override
  String toString() {
    var result = 'NatsException';
    if (message != null) result = '$result: $message';
    return result;
  }
}

/// A custom exception class for NKEYS-related errors.
///
/// This exception is thrown when operations related to NKEYS authentication
/// and signing encounter errors, such as invalid seeds, invalid public keys,
/// or signature verification failures.
///
/// Example:
/// ```dart
/// throw NkeysException('Invalid seed format');
/// ```
///
/// See also:
/// * [NatsException] - For general NATS-related errors
class NkeysException implements Exception {
  /// The error message describing what went wrong.
  final String? message;

  /// Creates a new [NkeysException] with an optional error [message].
  ///
  /// The [message] parameter provides details about what caused the NKEYS-related error.
  /// If omitted, a generic exception without a specific message is created.
  ///
  /// Example:
  /// ```dart
  /// throw NkeysException('Invalid seed format detected');
  /// ```
  ///
  /// See also:
  /// * [NatsException] - For general NATS errors
  NkeysException(this.message);

  /// Creates a new [NkeysException] with an optional error [message].
  ///
  /// The [message] parameter provides details about what caused the NKEYS-related error.
  /// If omitted, a generic exception without a specific message is created.
  ///
  /// Example:
  /// ```dart
  /// throw NkeysException('Invalid seed format detected');
  /// ```
  ///
  /// See also:
  /// * [NatsException] - For general NATS errors
  @override
  String toString() {
    var result = 'NkeysException';
    if (message != null) result = '$result: $message';
    return result;
  }
}
