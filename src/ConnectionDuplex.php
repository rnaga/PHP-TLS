<?php

namespace PTLS;

use PTLS\Record\BlockCipherRecord;
use PTLS\Record\AEADCipherRecord;
use PTLS\Record\Record;
use PTLS\Exceptions\TLSException;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class ConnectionDuplex
{
    public $random;
    public $MAC, $IV, $Key;
    public $isCipherChanged;

    private $core;
    private $record;
    private $cipherRecord;

    public function __construct(Core $core)
    {
        $this->core = $core;
        $this->record = new Record($this);
        $this->isCipherChanged = false;
    }

    public function getCore()
    {
        return $this->core;
    }

    /**
     * Switch over to cipher record
     */
    public function cipherChanged()
    {
        $core = $this->core;

        if( $core->cipherSuite->getCipherType() == CipherSuites::CIPHER_TYPE_AEAD )
            $this->cipherRecord = new AEADCipherRecord($this);
        else  
            $this->cipherRecord = new BlockCipherRecord($this);

        $this->isCipherChanged = true;
        return $this->cipherRecord;
    }

    /**
     * Set secret keys needed for encryption
     */
    public function setSecretKeys(array $secretKeys)
    {
        $this->MAC = $secretKeys['MAC'];
        $this->IV  = $secretKeys['IV'];
        $this->Key = $secretKeys['Key'];
    }

    public function getRecord()
    {
        if( $this->isCipherChanged )
            $record = $this->cipherRecord;
        else
            $record = $this->record;

        return $record;
    }

    public function getContentType()
    {
        $record = $this->getRecord();
        return $record->contentType;
    }

    public function encodeRecord($data)
    {
        while( !is_null($data) && strlen($data) > 0 )
        {
           $strlen = strlen($data);

           $record = $this->getRecord();
           $record->encode($data);
           $data = $record->get('dataRest');

           if( $strlen == strlen($data) )
               throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Failed on encodeRecord");           
       }
    }

    public function decodeRecord($data)
    {
        $core = $this->core;

        if(!$core->isHandshaked)
            throw new TLSException("Handshake is not finished");

        if( 0 >= strlen($data) )
            throw new TLSException("Empty output");

        $record = $this->getRecord();

        $record->set('contentType', ContentType::APPLICATION_DATA)
               ->set('payload', $data );

        return $record->decode();
    }
}



