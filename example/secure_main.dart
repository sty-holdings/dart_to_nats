import 'dart:io';

import 'package:dart_to_nats/dart_to_nats.dart';

void main() async {
  var client = Client();
  final securityContext = SecurityContext()
    ..setTrustedCertificates('../rootCA.pem')
    ..useCertificateChain('../client-cert.pem')
    ..usePrivateKey('../client-key.pem');

  await client.connect(Uri.parse('tls://localhost:4222'),
      securityContext: securityContext);

  // print(client.info?.toJson());
  var sub = client.sub('subject1');
  client.pubString('subject1', 'message1');
  var data = await sub.stream.first;

  print(data.string);
  client.unSub(sub);
  await client.close();
}
