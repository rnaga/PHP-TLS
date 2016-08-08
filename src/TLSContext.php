<?php

namespace PTLS;

class TLSContext
{
    public static function getServerConfig(array $arrConfig)
    {
        return new Config(Config::SERVER, $arrConfig);
    }

    public static function getClientConfig(array $arrConfig)
    {
        return new Config(Config::CLIENT, $arrConfig);
    }

    public static function createTLS(Config $config)
    {
        return new TLS($config->isServer(), $config);
    }
}
