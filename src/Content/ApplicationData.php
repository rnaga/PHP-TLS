<?php

namespace PTLS\Content;

use PTLS\Core;
use PTLS\ProtocolAbstract;

class ApplicationData extends ProtocolAbstract
{
    private $core;

    function __construct(Core $core)
    {
        $this->core = $core;
    }

    public function encode($data)
    {
         $this->core->getBufferIn()->append($data);
    }

    public function decode(){}

    public function debugInfo()
    {
        return  "[ApplicationData]\n"
              . "Data Length: " . $this->core->getBufferIn()->length();
    }
}

