<?php

namespace PTLS\Handshake;

use PTLS\Core;

class Certificate extends HandshakeAbstract
{
    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    public function encode($data)
    {
        $core = $this->core;

        $data = $this->encodeHeader($data);

        $crtsLength = Core::_unpack('N', $data[0] . $data[1] . $data[2] . 0x00 ) >> 8;
        $crtsData   = substr( $data, 3, $crtsLength );

        for( $i = 0; $i < $crtsLength; )
        {
            $crtLength = Core::_unpack('n', $crtsData[$i+1] . $crtsData[$i+2] );
            if( 0 >= (int)$crtLength ) break;

            $crtDers[] = substr($crtsData, $i+3, $crtLength);

            $i += $crtLength + 3;
        }

        $core->setCrtDers($crtDers);
    }

    public function decode()
    {
        $core = $this->core;
        $crtDers = $core->getCrtDers();

        $crtData = '';

        foreach( $crtDers as $crtDer )
        {
            $crtLength = strlen($crtDer);
    
            // Cert Length
            $crtData .= Core::_pack('C', 0x00 )
                      . Core::_pack('n', $crtLength )
                      . $crtDer;
        }

        $data = Core::_pack('C', 0x00 )
              . Core::_pack('n', strlen($crtData))
              . $crtData;

        $this->msgType = HandshakeType::CERTIFICATE;
        $this->length = strlen($data);

        return $this->getBinHeader() . $data;
    }

    public function debugInfo()
    {
        $core = $this->core;
        $crtDers = $core->getCrtDers();

        return "[HandshakeType::Certificate]\n"
             . "Lengh:                   " . $this->length . "\n"
             . "Number of Certificates:  " . count($crtDers) . "\n";
    }
}






