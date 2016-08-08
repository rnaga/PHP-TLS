<?php

namespace PTLS;

/**
 * https://tools.ietf.org/html/rfc5246#section-6.2
 * 6.2.  Record Layer
 *
 *   The TLS record layer receives uninterpreted data from higher layers
 *   in non-empty blocks of arbitrary size.
 *
 *    enum {
 *          change_cipher_spec(20), alert(21), handshake(22),
 *          application_data(23), (255)
 *      } ContentType;
 */
class ContentType
{
    const CHANGE_CIPHER_SPEC = 20;
    const ALERT              = 21;
    const HANDSHAKE          = 22;
    const APPLICATION_DATA   = 23;

    public static function getString($type)
    {
        switch($type)
        {
            case self::CHANGE_CIPHER_SPEC: return "CHANGE_CIPHER_SPEC";
            case self::ALERT: return "ALERT";
            case self::HANDSHAKE: return "HANDSHAKE";
            case self::APPLICATION_DATA: return "APPLICATION_DATA";
        }
 
        return "UNKNOWN";
    }
}

