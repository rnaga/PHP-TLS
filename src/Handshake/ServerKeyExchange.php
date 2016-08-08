<?php

namespace PTLS\Handshake;

use PTLS\Core;

class ServerKeyExchange extends HandshakeAbstract
{
    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    public function encode($data)
    {
        $core = $this->core;
        $extensions = $core->extensions;

        $this->encodeHeader($data);

        if( $core->cipherSuite->isECDHEEnabled() )
        {
            $extensions->call('Curve', 'encodeServerKeyExchange', null, $data);
        }
    }

    public function decode()
    {
        // Extensions\Curve::decodeServerKeyExchange
    }

    public function debugInfo()
    {
        return "[HandshakeType::ServerKeyExchange]\n"
             . "Lengh: " . $this->length . "\n";
    }
}

