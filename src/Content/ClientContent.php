<?php

namespace PTLS\Content;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\Handshake\HandshakeType;
use PTLS\Handshake\HandshakeFactory;
use PTLS\Exceptions\TLSAlertException;

class ClientContent extends ContentAbstract
{
    function __construct(Core $core)
    {
        parent::__construct($core);

        $recordOut = $core->getOutDuplex()->getRecord();
        $bufferOut = $core->getBufferOut();

        // ===========================================
        // Send Client Hello
        // =========================================== 
        $clientHello = HandshakeFactory::getInstance($core, HandshakeType::CLIENT_HELLO);
        $payload = $clientHello->decode();

        $bufferOut->set( $this->decodeContent($payload, ContentType::HANDSHAKE) );

        $this->expectedHandshakeType = HandshakeType::SERVER_HELLO;
    }

    public function encodeHandshake($payload)
    {
        $core = $this->core;

        // Incomming Record
        $recordIn  = $core->getInDuplex()->getRecord();

        // Outgoing Record
        $recordOut = $core->getOutDuplex()->getRecord();

        // Buffer to send
        $bufferOut = $core->getBufferOut();

        // Extension
        $extensions = $core->extensions;

        if( $core->isHandshaked )
            throw new TLSAlertException(Alert::create(Alert::UNEXPECTED_MESSAGE), 
                "Handshake message received after handshake is complete");
        /*
         * https://tools.ietf.org/html/rfc5246#section-7.4
         *
         * Get Handshake Msg type
         */
        $handshakeType = Core::_unpack('C', $payload[0] );

        if( $this->expectedHandshakeType != $handshakeType )
            throw new TLSAlertException(Alert::create(Alert::UNEXPECTED_MESSAGE), 
                "Unexpected handshake message: $handshakeType <=> " . $this->expectedHandshakeType);

        $handshake = HandshakeFactory::getInstance($core, $handshakeType);

        $handshake->encode($payload);

        $this->content = $handshake;

        switch($this->expectedHandshakeType)
        {
            case HandshakeType::SERVER_HELLO:
                $this->expectedHandshakeType = HandshakeType::CERTIFICATE;
                break;

            case HandshakeType::CERTIFICATE:

                if( $core->cipherSuite->isECDHEEnabled() )
                    $this->expectedHandshakeType = HandshakeType::SERVER_KEY_EXCHANGE;
                else
                    $this->expectedHandshakeType = HandshakeType::SERVER_HELLO_DONE;
                break;

            case HandshakeType::SERVER_KEY_EXCHANGE:
                $this->expectedHandshakeType = HandshakeType::SERVER_HELLO_DONE;
                break;

            case HandshakeType::SERVER_HELLO_DONE:

                // ===========================================
                // Send Client Key Exchange
                // =========================================== 
                $clientKeyExchange = HandshakeFactory::getInstance($core, HandshakeType::CLIENT_KEY_EXCHANGE);
                $bufferOut->set( $this->decodeContent($clientKeyExchange->decode(), ContentType::HANDSHAKE) );

                // ===========================================
                // Send Change Cipher Spec
                // ===========================================
                $changeCipherSpec = new ChangeCipherSpec();
    
                $bufferOut->append( $this->decodeContent($changeCipherSpec->decode(),  ContentType::CHANGE_CIPHER_SPEC ) ); 
    
                // Enable encryption
                $recordOut->cipherChanged();
    
                // ===========================================
                // Send Client finished
                // =========================================== 
                $clientFinished = HandShakeFactory::getInstance($core, HandshakeType::FINISHED);
    
                $bufferOut->append( $this->decodeContent($clientFinished->decode(), ContentType::HANDSHAKE) ); 
    
                $this->expectedHandshakeType = HandshakeType::FINISHED;
                break;

            case HandshakeType::FINISHED:
                $core->isHandshaked = true; 
                break;

        }

        if( strlen($payload) > $handshake->get('length') )
        {
            $payload = substr($payload, $handshake->get('length'));
            $this->encodeHandshake($payload);
        }
    }
}

