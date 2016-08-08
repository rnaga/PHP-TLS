<?php

namespace PTLS;

use PTLS\Exceptions\TLSAlertException;
use PTLS\Exceptions\TLSException;

class TLS implements DataConverterInterface
{
    private $core;
    private $bufferOut;

    function __construct(bool $isServer, Config $config)
    {
        $this->core = new Core($isServer, $config);
        $this->bufferOut = new Buffer();
    }

    public function isHandshaked()
    {
        return $this->core->isHandshaked;
    }   

    public function isClosed()
    {
        return $this->core->isClosed;
    }

    public function input()
    {
        $core = $this->core;
        return $core->getBufferIn()->flush();
    }

    public function encode($data)
    {
        $core = $this->core;

        $in = $core->getInDuplex();

        try{
            $in->encodeRecord($data);
        }
        catch(TLSAlertException $e)
        {
            // Set output if any
            $e->setOutput($core);

            // Re-throw so that the upper layer can catch it
            throw $e;
        }
    }

    public function decode()
    {
        $core = $this->core;
        $coreBufferOut = $core->getBufferOut();
        
        $out = '';

        if( $coreBufferOut->length() > 0 )
            $out = $coreBufferOut->flush();

        if( !$core->isHandshaked )
            return $out;

        $payload = $this->bufferOut->flush();

        if( 0 >= strlen($payload) )
            return $out;

        $connOut = $core->getOutDuplex();

        $out .= $connOut->decodeRecord($payload);

        return $out;
    }

    public function output($data, $isAppend = false)
    {
       $core   = $this->core;
       $bufferOut = $this->bufferOut;

       if( !$core->isHandshaked )
           throw new TLSException('Handshake is not done');

       if( $isAppend )
           $bufferOut->append($data);
       else
           $bufferOut->set($data); 

       return $this;
    }

    public function append($data)
    {
        return $this->setOutput($data, true);
    }

    public function getDebug()
    {
        return new Debug($this->core);
    }
}
