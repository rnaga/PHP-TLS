<?php

namespace PTLS\Content;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\Handshake\HandshakeType;
use PTLS\Handshake\HandshakeFactory;
use PTLS\Exceptions\TLSAlertException;

class ServerContent extends ContentAbstract
{
    function __construct(Core $core)
    {
        $this->core = $core;
        $this->expectedHandshakeType = HandshakeType::CLIENT_HELLO;
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

        /*
         * https://tools.ietf.org/html/rfc5246#section-7.4
         *
         * Get Handshake Msg type
         */
        $handshakeType = Core::_unpack('C', $payload[0] );

        if( $core->isHandshaked )
        {
            throw new TLSAlertException(Alert::create(Alert::UNEXPECTED_MESSAGE),
                "Handshake message received after handshake is complete: $handshakeType");
        }

        if( $this->expectedHandshakeType != $handshakeType )
            throw new TLSAlertException(Alert::create(Alert::UNEXPECTED_MESSAGE), "Unexpected handshake message");

        $handshake = HandshakeFactory::getInstance($core, $handshakeType);

        $handshake->encode($payload);

        $this->content = $handshake;

        // Set the response into bufferOut if any
        switch($this->expectedHandshakeType)
        {
            case HandshakeType::CLIENT_HELLO:

                // ===========================================
                // Send Server Hello
                // =========================================== 
                $serverHello = HandshakeFactory::getInstance($core, HandshakeType::SERVER_HELLO);
    
                $bufferOut->set( $this->decodeContent($serverHello->decode(), ContentType::HANDSHAKE) );    

                // ===========================================
                // Send Certificate
                // ===========================================  
                $certificate = HandshakeFactory::getInstance($core, HandshakeType::CERTIFICATE);
    
                $bufferOut->append( $this->decodeContent($certificate->decode(), ContentType::HANDSHAKE) );    

                // ===========================================
                // Send Server Key Exchange
                // ===========================================
                if( $core->cipherSuite->isECDHEEnabled() )
                {
                    $curveOut = $extensions->call('Curve', 'decodeServerKeyExchange', null);
                    $bufferOut->append( $this->decodeContent($curveOut, ContentType::HANDSHAKE) );
                }
    
                // ===========================================
                // Send Server Hello Done
                // =========================================== 
                $serverHelloDone = HandshakeFactory::getInstance($core, HandshakeType::SERVER_HELLO_DONE);
    
                $bufferOut->append( $this->decodeContent($serverHelloDone->decode(), ContentType::HANDSHAKE) );

                // Update state
                $this->expectedHandshakeType = HandshakeType::CLIENT_KEY_EXCHANGE;

                break;
        
            case HandshakeType::CLIENT_KEY_EXCHANGE:
                $this->expectedHandshakeType = HandshakeType::FINISHED;
                break;
        
            case HandshakeType::FINISHED:

                // ===========================================
                // Send Change Cipher Spec
                // ===========================================
                $changeCipherSpec = new ChangeCipherSpec();
  
                $bufferOut->set( $this->decodeContent( $changeCipherSpec->decode(), ContentType::CHANGE_CIPHER_SPEC) ); 

                // Enable encryption
                $recordOut->cipherChanged();
    
                // ===========================================
                // Send Server finished
                // =========================================== 
                $serverFinished = HandShakeFactory::getInstance($core, HandshakeType::FINISHED);
    
                $bufferOut->append( $this->decodeContent(  $serverFinished->decode(), ContentType::HANDSHAKE) );    

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

