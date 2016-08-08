<?php

namespace PTLS;

interface DataConverterInterface
{
    /**
     * Unserialize
     */
    function encode($data);

    /**
     *  Serialize to TLS format
     */
    function decode();
}
