<?php

namespace PTLS\Content;

use PTLS\Core;
use PTLS\ProtocolAbstract;

/**
  * https://tools.ietf.org/html/rfc5246#section-7.1
  *
  *   The change cipher spec protocol exists to signal transitions in
  *   ciphering strategies.  The protocol consists of a single message,
  *   which is encrypted and compressed under the current (not the pending)
  *   connection state.  The message consists of a single byte of value 1.
  *
  *      struct {
  *          enum { change_cipher_spec(1), (255) } type;
  *      } ChangeCipherSpec;
 */
class ChangeCipherSpec extends ProtocolAbstract
{
    public function encode($data)
    {
        $msg = Core::_unpack('C', $data[0]);
    }

    public function decode()
    {
        return Core::_pack('C', 0x01);
    }

    public function debugInfo()
    {
        return "[ChangeCipherSpec]\n";
    }
}

