<?php

namespace PTLS\Handshake;

use PTLS\Core;

class ServerHelloDone extends HandshakeAbstract
{
    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    public function encode($data){}

    public function decode()
    {
        $this->msgType = 14;
        $this->length = 0;

        return $this->getBinHeader();
    }

    public function debugInfo()
    {
        return "[HandshakeType::ServerHelloDone]\n";
    }
}

