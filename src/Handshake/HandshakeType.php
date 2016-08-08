<?php

namespace PTLS\Handshake;

/**
 *      enum {
 *          hello_request(0), client_hello(1), server_hello(2),
 *          certificate(11), server_key_exchange (12),
 *          certificate_request(13), server_hello_done(14),
 *          certificate_verify(15), client_key_exchange(16),
 *          finished(20), (255)
 *      } HandshakeType;
 * struct {
 *          HandshakeType msg_type; 
 *          uint24 length;      
 *          select (HandshakeType) {
 *              case hello_request:       HelloRequest;
 *              case client_hello:        ClientHello;
 *              case server_hello:        ServerHello;
 *              case certificate:         Certificate;
 *              case server_key_exchange: ServerKeyExchange;
 *              case certificate_request: CertificateRequest;
 *              case server_hello_done:   ServerHelloDone;
 *              case certificate_verify:  CertificateVerify;
 *              case client_key_exchange: ClientKeyExchange;
 *              case finished:            Finished;
 *          } body;
 *      } Handshake;
 *
 * NO support for certificate_request(13) and certificate_verify(15)
 */
class HandshakeType
{
    const HELLO_REQUEST       = 0;
    const CLIENT_HELLO        = 1;
    const SERVER_HELLO        = 2;
    const CERTIFICATE         = 11;
    const SERVER_KEY_EXCHANGE = 12;
    const SERVER_HELLO_DONE   = 14;
    const CLIENT_KEY_EXCHANGE = 16;
    const FINISHED            = 20;
}

