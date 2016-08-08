<?php

namespace PTLS;

abstract class ProtocolAbstract implements DataConverterInterface
{
    protected $length;
    protected $payload;

    abstract public function debugInfo();

    /**
     * Get properties
     */
    public function get($property, $default = null)
    {
        if( property_exists($this, $property) )
            return $this->$property;

        return $default;
    }

    /**
     * Set properties
     */
    public function set($property, $value)
    {
        $this->$property = $value;
        return $this;
    }
}

