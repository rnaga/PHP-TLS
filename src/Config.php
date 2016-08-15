<?php

namespace PTLS;

use PTLS\Exceptions\TLSException;

class Config
{
    const SERVER = true;
    const CLIENT = false;

    private $config;
    private $isServer;

    function __construct(bool $isServer, array $arrConfig)
    {
        $this->isServer = $isServer;
        $this->config   = [];

        if( $isServer )
            $this->encodeServerConfig($arrConfig);
        else
            $this->encodeClientConfig($arrConfig);
    }

    private function encodeClientConfig(array $arrConfig)
    {
        // Setting up TLS version
        if( isset( $arrConfig['version'] ) )
            $this->config['version'] = $arrConfig['version'];
    }

    private function encodeServerConfig(array $arrConfig)
    {
        if( !isset( $arrConfig['key_pair_files'] ) )
            throw new TLSException("No keyPairFiles");

        $keyPairFiles = $arrConfig['key_pair_files'];

        if( !isset( $keyPairFiles['cert']) || !isset( $keyPairFiles['key'] ) )
            throw new TLSException("Invalid keyPair");

        $pemCrtFiles     = $keyPairFiles['cert'];
        $pemPriFile      = $keyPairFiles['key'][0];
        $pemPriPassCode  = $keyPairFiles['key'][1];

        $this->config['crt_ders']    = X509::crtFilePemToDer($pemCrtFiles);
        $this->config['private_key'] = X509::getPrivateKey($pemPriFile, $pemPriPassCode);
    }

    public function get($key, $default = null)
    {
        return ( isset($this->config[$key] ) ) ? $this->config[$key] : $default;
    }

    public function isServer()
    {
        return $this->isServer;
    }
}

