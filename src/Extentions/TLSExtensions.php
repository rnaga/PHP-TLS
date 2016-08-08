<?php

namespace PTLS\Extensions;

use PTLS\Core;

/**
 * https://tools.ietf.org/html/rfc5246#section-7.4.1.4
 * Hello Extensions
 */
class TLSExtensions
{
    const TYPE_ELLIPTIC_CURVES  = 10;
    const TYPE_EC_POINT_FORMATS = 11;
    const TYPE_SIGNATURE_ALGORITHM = 13;

    public static $supportedList = [
        self::TYPE_ELLIPTIC_CURVES      => 'Curve',
        self::TYPE_EC_POINT_FORMATS     => 'Curve',
        self::TYPE_SIGNATURE_ALGORITHM  => 'SignatureAlgorithm',
    ];

    private $core;
    private $instances;

    public function __construct(Core $core)
    {
        $this->core = $core;
        $this->instances = [];

        foreach(self::$supportedList as $type => $className)
        {
            if( isset( $this->instances[$className] ) )
                continue;

            $this->instances[$className] = $this->getExtension($type);
        }
    }

    private function getExtension($type)
    {
        switch($type)
        {
            case self::TYPE_ELLIPTIC_CURVES:
            case self::TYPE_EC_POINT_FORMATS:
                return new Curve($this->core);
            case self::TYPE_SIGNATURE_ALGORITHM:
                return new SignatureAlgorithm($this->core);
        } 

        return null;
    }

    private function onEncode(string $method, array $extensions)
    {
        // $extensions[] = ['type' => $extType, 'data' => $extData];
        foreach( $extensions as $extension )
        {
            if( !isset( $extension['type'] ) || !isset( $extension['data'] ) )
                throw new Exception("Invalid Extension Paramenter");

            $type = $extension['type'];
            $data = $extension['data'];

            if( array_key_exists( $type, self::$supportedList ) )
            {
                $className = self::$supportedList[$type];

                if( !isset( $this->instances[$className] ) )
                    $this->instances[$className] = $this->getExtension($type);

                $ins = $this->instances[$className];

                if( !$ins instanceof ExtensionAbstract )
                    throw new Exception("Not ExtensionAbstract");

                [$ins, $method]($type, $data);
            }
        }
    }

    private function onDecode(string $method)
    {
        $out = '';

        if( !count( $this->instances ) )
        {
            return $out;
        }

        foreach( $this->instances as $className => $ins )
        {
            $out .= [$ins, $method]();
        }

        return $out;
    }

    public function __call(string $method, array $args)
    {
        if( false !== strpos($method, 'onEncode') )
        {
            return $this->onEncode($method, $args[0]);
        }

        if( false !== strpos($method, 'onDecode') )
        {
            return $this->onDecode($method);
        }
    }

    /**
     * API call
     */
    public function call($className, $method, $default, ...$args)
    {
        if( isset( $this->instances[$className] ) && 
            is_callable( [$this->instances[$className], $method] ) )
        {
            return [$this->instances[$className], $method](...$args);
        }

        return $default;
    }
}





