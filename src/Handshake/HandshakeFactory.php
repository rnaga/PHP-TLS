<?php

namespace PTLS\Handshake;

use PTLS\Core;
use PTLS\Handshake\HandshakeType;
use PTLS\Exceptions\TLSAlertException;

abstract class HandshakeFactory
{
    public static function getInstance(Core $core, int $type)
    {
        switch( $type )
        {
            case HandshakeType::HELLO_REQUEST:
                return new HelloRequest($core);
            case HandshakeType::CLIENT_HELLO:
                return new ClientHello($core);
            case HandshakeType::SERVER_HELLO:
                return new ServerHello($core);
            case HandshakeType::SERVER_HELLO_DONE:
                return new ServerHelloDone($core);
            case HandshakeType::CERTIFICATE:
                return new Certificate($core);
            case HandshakeType::CLIENT_KEY_EXCHANGE:
                return new ClientKeyExchange($core);
            case HandshakeType::FINISHED:
                return new Finished($core);
            case HandshakeType::SERVER_KEY_EXCHANGE:
                return new ServerKeyExchange($core);
        }

        throw new TLSAlertException(Alert::create(Alert::UNEXPECTED_MESSAGE), "Unknow Handshake Type: $type");
    }
}

