<?php

namespace PTLS\Extensions;

use PTLS\Core;

abstract class ExtensionAbstract
{
    private $core;
    protected $extType;
    protected $legnth;

    public function __construct(Core $core)
    {
        $this->core = $core;
    }

    protected function decodeHeader()
    {
                  // MsgType
        $header = Core::_pack('C', 0 ) 
                . Core::_pack('C', $this->extType)
                  // Length
                . Core::_pack( 'n', $this->length );

        return $header;
    }

    abstract public function onEncodeClientHello($type, $data);
    abstract public function onDecodeClientHello();
    abstract public function onDecodeServerHello();
}
