# PHP TLS

TLS library written in PHP.

Features:
  - TLSv1.1 and TLSv1.2
  - ECDHE(secp256r1, secp384r1)
  - Signature Alogorithm(TLSv1.2)

Supported Cipher Suite:
  - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  - TLS_RSA_WITH_AES_256_CBC_SHA256,
  - TLS_RSA_WITH_AES_256_CBC_SHA,
  - TLS_RSA_WITH_AES_128_CBC_SHA256,
  - TLS_RSA_WITH_AES_128_CBC_SHA

Usage:

```php
// Create a TLS Engine
$tls = TLSContext::createTLS(TLSContext::getServerConfig([]));

// Receive raw data from a client
$data = stream_socket_recvfrom($clientSocket);

// Pass raw data to TLS Engine for conversion
$tls->encode($data);

// Get the plaintext from TLS Engine
$in = $tls->input();

// Convert plaintext into TLS format
$out = $tls->output("Hello World)->decode();

// Send the output to a client
stream_socket_sendto($clientSocket, $out);

```
