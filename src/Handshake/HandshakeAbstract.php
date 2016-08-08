<?php

namespace PTLS\Handshake;

use PTLS\Core;
use PTLS\ProtocolAbstract;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

abstract class HandshakeAbstract extends ProtocolAbstract
{
    protected $msgType;
    protected $core;
    
    function __construct(Core $core)
    {
        $this->core = $core;
    }

    public function encodeHeader($data)
    {
        // https://tools.ietf.org/html/rfc5246#section-7.4
        $this->msgType = $msgType = Core::_unpack( 'C', $data[0] );
        $this->length  = $length  = Core::_unpack( 'N', $data[1] . $data[2] . $data[3] . 0x00 ) >> 8;

        $data = substr($data, 4, $length);
  
        $this->payload = $data;

        if( $this->length != strlen($data) )
            throw new TLSAlertException(Alert::create(Alert::ILLEGAL_PARAMETER), "Invalid Handshake payload: " . $this->length);

        return $data;
    }

    // @Override
    public function get($property, $default = null)
    {
        if( $property == 'length' )
            return $this->length + 4;

        parent::get($property, $default);
    }

    public function getBinHeader()
    {
                  // MsgType
        $header = Core::_pack('C', $this->msgType)
                  // Length
                . Core::_pack('C', 0x00 )
                . Core::_pack( 'n', $this->length );

        return $header;
    }

    public function setMsgType($msgType)
    {
        $this->msgType = $msgType;
    }

    /**
     * for Client Hello and Server Hello
     */
    protected function encodeExtensions($data)
    {
        $extensions = [];

        for( $j = 0; $j < strlen($data); )
        {
            $extType = Core::_unpack( 'n', $data[$j] . $data[$j+1] );
            $extDataLen = Core::_unpack( 'n', $data[$j+2] . $data[$j+3] );

            if( 0 == $extDataLen )
            {
                $j += 2 + 2;
                continue;
            }

            $extData = substr( $data, $j+4, $extDataLen );

            $j += 2 + 2 + $extDataLen;

            $extensions[] = ['type' => $extType, 'data' => $extData];
        }

        return $extensions;
    }
}




