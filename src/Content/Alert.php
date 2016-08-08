<?php

namespace PTLS\Content;

use PTLS\Core;
use PTLS\ProtocolAbstract;

/**
 * https://tools.ietf.org/html/rfc5246#section-7.2
 */
class Alert extends ProtocolAbstract
{
    const CLOSE_NOTIFY                = 0;
    const UNEXPECTED_MESSAGE          = 10;
    const BAD_RECORD_MAC              = 20;
    const DECRYPTION_FAILED_RESERVED  = 21;
    const RECORD_OVERFLOW             = 22;
    const DECOMPRESSION_FAILURE       = 30;
    const HANDSHAKE_FAILURE           = 40;
    const NO_CERTIFICATE_RESERVED     = 41;
    const BAD_CERTIFICATE             = 42;
    const UNSUPPORTED_CERTIFICATE     = 43;
    const CERTIFICATE_REVOKED         = 44;
    const CERTIFICATE_EXPIRED         = 45;
    const CERTIFICATE_UNKNOWN         = 46;
    const ILLEGAL_PARAMETER           = 47;
    const UNKNOWN_CA                  = 48;
    const ACCESS_DENIED               = 49;
    const DECODE_ERROR                = 50;
    const DECRYPT_ERROR               = 51;
    const EXPORT_RESTRICTION_RESERVED = 60;
    const PROTOCOL_VERSION            = 70;
    const INSUFFICIENT_SECURITY       = 71;
    const INTERNAL_ERROR              = 80;
    const USER_CANCELED               = 90;
    const NO_RENEGOTIATION            = 100;
    const UNSUPPORTED_EXTENSION       = 110;

    // enum { warning(1), fatal(2), (255) } AlertLevel;
    const LEVEL_WARNING = 1;
    const LEVEL_FATAL   = 2;

    private $descCode;
    private $level;
    private $fromPeer;

    public static function create(int $descCode, int $level = self::LEVEL_FATAL)
    {
        $alert = new Alert();
        $alert->descCode = $descCode;
        $alert->level    = $level;
        $alert->fromPeer = false;

        return $alert;
    }

    public static function getConst($value)
    {
        $class = new \ReflectionClass(__CLASS__);
        $constants = array_flip($class->getConstants());

        return $constants[$value];
    } 

    public function getDescCode()
    {
        return $this->descCode;
    }

    public function fromPeer()
    {
        return $this->fromPeer;
    }

    public function encode($data)
    {
        $this->level    = Core::_unpack('C', $data[0]);
        $this->descCode = Core::_unpack('C', $data[1]);

        // We got alert message from peer
        $this->fromPeer = true;
    }

    public function decode()
    {
        return Core::_pack('C', $this->level) 
             . Core::_pack('C', $this->descCode);
    }

    public function toString()
    {
        $desc = $this->getConst($this->descCode);
        $msg = $desc . " " . $this->descCode;

        return $msg;
    }

    public function debugInfo(){ $this->toString(); }
}





