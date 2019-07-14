<?php

namespace PTLS;

class Debug
{
    private $core;

    function __construct(Core $core)
    {
        $this->core = $core;        
    }

    public function getProtocolVersion()
    {
        list($vMajor, $vMinor) = $this->core->getVersion();
        return "1." . ($vMinor - 1);
    }

    public function getCertificates()
    {
        $crtDers = $this->core->getCrtDers();

        if( !count( $crtDers ) ) return '';

        $output = [];

        foreach( $crtDers as $der )
        {
            $output[] = X509::crtDerToPem($der);
        }

        return implode("\n", $output) . "\n";
    }

    public function getPrivateKey()
    {
        if( !$this->core->isServer )
            return;

        return $this->core->getConfig('private_key');
    }

    public function getUsingCipherSuite()
    {
        if( is_null( $this->core->cipherSuite ) )
            return;

        return $this->core->cipherSuite->debugInfo();
    }

    public function getSessionID()
    {
        return $this->core->getSessionID();
    }

    public function getMasterSecret()
    {
        return $this->core->getMasterSecret();
    }

    public function getRecordStatus()
    {
        $recordIn = $this->core->getInDuplex()->getRecord();
        return "=================RecordStatus===================\n"
             . $recordIn->debugInfo()
             . "\n================================================\n";
    }

}



