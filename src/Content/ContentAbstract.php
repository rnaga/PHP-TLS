<?php

namespace PTLS\Content;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\Handshake\HandshakeType;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Exceptions\TLSException;

abstract class ContentAbstract
{
    protected $expectedHandshakeType;
    protected $core;
    protected $content;
    protected $appData;

    abstract public function encodeHandshake($data);

    function __construct(Core $core)
    {
        $this->core = $core;
        $this->content = 
        $this->appData = null;
    }

    /**
     * https://tools.ietf.org/html/rfc5246#section-6.2.1
     *
     *      enum {
     *          change_cipher_spec(20), alert(21), handshake(22),
     *          application_data(23), (255)
     *      } ContentType;
     */
    public function encodeContent($contentType, $payload, $record)
    {
        $core = $this->core;

        switch($contentType)
        {
            case ContentType::HANDSHAKE:

                // Count handshake for later to create finished message
                $core->countHandshakeMessages($payload);

                $this->encodeHandshake($payload);
                break;

            case ContentType::CHANGE_CIPHER_SPEC:
                $this->encodeChangeCipherSpec($payload);
                $record->cipherChanged();
                break;
        
            case ContentType::ALERT:
                $this->encodeAlert($payload);
                break;

            case ContentType::APPLICATION_DATA:
                $this->encodeApplicationData($payload);
                break;

            /*
             * https://tools.ietf.org/html/rfc5246#section-6
             *
             * If a TLS implementation receives an unexpected record type, it MUST send an
             * unexpected_message alert.
             */
            default:
                throw new TLSAlertException(Alert::create(Alert::UNEXPECTED_MESSAGE), "Unknow Content Type: $contentType");
        }
    }

    protected function decodeContent($payload, int $contentType)
    {
        $core = $this->core;

        $recordOut = $core->getOutDuplex()->getRecord(); 

        $out = $recordOut->set('contentType', $contentType)
                         ->set('payload', $payload )
                         ->decode();

        return $out;
    }

    public function encodeChangeCipherSpec($data)
    {
        $core = $this->core;

        if( $this->expectedHandshakeType != HandshakeType::FINISHED || $core->isHandshaked )
            throw new TLSException("Invalid message");

        $changeCipherSpec = new ChangeCipherSpec();
        $changeCipherSpec->encode($data);

        $this->content = $changeCipherSpec;
    }

    public function encodeApplicationData($data)
    {
        $core = $this->core;

        if( !$core->isHandshaked )
            throw new TLSException("Handshake Imcomplete");

        if( is_null( $this->appData ) )
            $this->appData = new ApplicationData($this->core);

        $this->appData->encode($data);
    }

    public function encodeAlert($data)
    {
        $core = $this->core;

        $alert = new Alert();
        $alert->encode($data);

        $this->content = $alert;

        $core->isClosed = true;        

        if( $alert->getDescCode() != Alert::CLOSE_NOTIFY )
            throw new TLSAlertException($alert, "Alert received from peer");
    }

    public function debugInfo()
    {
        if( is_null( $this->content ) ) return;
        return $this->content->debugInfo();
    }
}






