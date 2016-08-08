<?php

namespace PTLS\Record;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\ProtocolAbstract;
use PTLS\ConnectionDuplex;
use PTLS\Buffer;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

/**
 * https://tools.ietf.org/html/rfc5246#section-6.2.1
 */
class Record extends ProtocolAbstract
{
    const MAX_LENGTH = 17408; // 2^14 + 1024
    const MAX_BUFFER_LENGTH = 34816; // 17408 * 2 

    public $contentType;
    
    protected $conn;
    protected $dataRest;
    protected $maxLength;

    private $encodeBuffer;

    public function __construct(ConnectionDuplex $conn)
    {
        $this->conn = $conn;
        $this->encodeBuffer = new Buffer();
        $this->maxLength = self::MAX_LENGTH;
    }

    public function getCore()
    {
        return $this->conn->getCore();
    }

    public function getConn()
    {
        return $this->conn;
    }

    /**
     * Delegation to ConnectionDuplex::cipherChanged()
     */
    public function cipherChanged()
    {
        return $this->conn->cipherChanged();
    }

    protected function encodeHeader($data)
    {
        $data = $this->encodeBuffer->flush() . $data;

        $this->contentType = Core::_unpack( 'C', $data[0] );

        $vMajor = Core::_unpack( 'C', $data[1] );
        $vMinor = Core::_unpack( 'C', $data[2] );

        $this->length = Core::_unpack( 'n', $data[3] . $data[4] );

        if( $this->length > $this->maxLength )//|| strlen($data) > self::MAX_BUFFER_LENGTH )
        {
            /*
             * A TLSCiphertext record was received that had a length more than
             * 2^14+2048 bytes, or a record decrypted to a TLSCompressed record
             * with more than 2^14+1024 bytes.
             */
            throw new TLSAlertException(Alert::create(Alert::RECORD_OVERFLOW), "Exceed max length of payload: " . strlen($data) );
        }

        if( $this->length > strlen( $data ) )
        {
            $this->encodeBuffer->set($data);
            return false;
        }

        $this->payload  = substr($data, 5, $this->length);
        $this->dataRest = substr($data, 5 + $this->length);

        return true;
    }

    protected function encodeContent()
    {
        $core = $this->getCore();
        $content = $core->content;

        $content->encodeContent($this->contentType, $this->payload, $this);
    }

    public function encode($data)
    {
        $this->reset();

        if( !$this->encodeHeader($data) )
            return;

        $this->encodeContent();
    }

    /**
     * @Override
     */
    public function get($property, $default = null)
    {
        if( $property == 'length' )
        {
            return 5 + $this->length;
        }

        return parent::get($property);
    }

    /**
     * @Override
     */
    public function set($property, $value)
    {
        parent::set($property, $value);

        if( $property == 'payload' )
        {
            $this->length = strlen($this->payload);
        }

        return $this;
    }

    public function reset()
    {
        $this->contentType =
        $this->dataRest =
        $this->payload = null;

        $this->length = -1;
    }

    public function decode()
    {
        $core = $this->getCore();

        list($vMajor, $vMinor) = $core->getVersion();

        // type
        $data = Core::_pack('C', $this->contentType)
              . Core::_pack('C', $vMajor)
              . Core::_pack('C', $vMinor)
              . Core::_pack('n', $this->length)
              . $this->payload;

        // Handshake
        if( $this->contentType == ContentType::HANDSHAKE && !$this->conn->isCipherChanged )
            $core->countHandshakeMessages($this->payload);

        $this->reset();

        return $data;
    }

    public function debugInfo()
    {
        $core = $this->getCore();

        $outputs[] = "ContentType:      " . ContentType::getString($this->contentType);
        $outputs[] = "Length:           " . $this->length;
        $outputs[] = "Received Payload: " . strlen($this->payload);

        $r = "[Record Protocol]\n" . implode("\n", $outputs) . "\n"
           . "[Content]\n" . $core->content->debugInfo();
     
        return $r;
    }
}






