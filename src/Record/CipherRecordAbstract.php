<?php

namespace PTLS\Record;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\ConnectionDuplex;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

abstract class CipherRecordAbstract extends Record
{
    const MAX_CIPHER_LENGTH = 18432; // 2^14 + 2048

    protected $seq;
    protected $encPayload;
    protected $encLength;

    public function __construct(ConnectionDuplex $conn)
    {
        parent::__construct($conn);
        $this->maxLength = self::MAX_CIPHER_LENGTH;
    }

    /**
     * @Override
     */
    public function get($property, $default = null)
    {
        if( $property == 'length' )
        {
            return 5 + $this->encLength;
        }

        return parent::get($property);
    }

    protected function getSeq()
    {
        if( is_null( $this->seq ) )
        {
            $this->seq = self::getZeroSeq();
        }

        return implode('', $this->seq );
    }

    protected function incrementSeq()
    {
        if( is_null( $this->seq ) )
        {
            $this->seq = $this->getZeroSeq();
        }

        for( $i = 7; $i >= 0; $i--)
        {
            $num = Core::_unpack('C', $this->seq[$i]) + 1;
            $this->seq[$i] = Core::_pack('C', $num );

            if( $num%256 > 0 ) break;
        }
    }

    protected static function getZeroSeq()
    {
        $seq = [];
        for($i = 0; $i < 8; $i++)
            $seq[$i] = Core::_pack('C', 0);

        return $seq;
    }

}


