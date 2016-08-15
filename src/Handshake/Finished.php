<?php

namespace PTLS\Handshake;

use PTLS\Core;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class Finished extends HandshakeAbstract
{
    const PRF_LENGTH = 12;

    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    private function getVerifyData($isServer = false, $handshakeMessages)
    {
        $core = $this->core;

        $protoVersion = $core->getProtocolVersion();

        $finishedLabel = ( $isServer ) ? "server finished" : "client finished";
        $prf = $core->prf;

        /*
         * [TLS 1.1]
         * https://www.ietf.org/rfc/rfc2246.txt 7.4.9
         * verify_data
         *   PRF(master_secret, finished_label, MD5(handshake_messages) +
         *   SHA-1(handshake_messages)) [0..11];
         */
        if( $protoVersion == 31 )
        {
            $seedHash = md5($handshakeMessages, true) . sha1($handshakeMessages, true);
        }
        /*
         * [TLS 1.2] 
         * 7.4.0 https://tools.ietf.org/html/rfc5246
         * verify_data
         * PRF(master_secret, finished_label, Hash(handshake_messages))
         *    [0..verify_data_length-1];
        */
        else // 1.2
        {
            $cipherSuite = $core->cipherSuite;
            $seedHash = hash($cipherSuite->getHashAlogV33(), $handshakeMessages, true);
        }

        $masterSecret = $core->getMasterSecret();

        $verifyData = $prf->prf(self::PRF_LENGTH, $masterSecret, $finishedLabel, $seedHash);

        return $verifyData;
    }

    public function encode($data)
    {
        $core = $this->core;

        $data = $this->encodeHeader($data);
       
        /*
         * https://tools.ietf.org/html/rfc5246#section-7.4.9
         *
         * Note that this
         * representation has the same encoding as with previous versions.
         * Future cipher suites MAY specify other lengths but such length
         * MUST be at least 12 bytes.
         */
        $this->verifyData = substr($data, 0, $this->length);

        // Get all handshakeMessages excluding this message
        $handshakeMessages = $core->getHandshakeMessages(1);

        // Get verify data
        $verifyData = $this->getVerifyData($core->isServer ^ true, $handshakeMessages);

        if( $this->verifyData != $verifyData )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), 
                "Handshake Finished: verifyData mismatched:" . base64_encode( $this->verifyData ) . "<=>" . base64_encode( $verifyData ));
    }

    public function decode()
    {
        $core = $this->core;

        $handshakeMessages = $core->getHandshakeMessages();

        $verifyData = $this->getVerifyData($core->isServer, $handshakeMessages);

        $this->msgType = 20;
        $this->length = strlen($verifyData);
        return $this->getBinHeader() . $verifyData;
    }

    public function debugInfo()
    {
        /*
         * struct {
         *  opaque verify_data[verify_data_length];
         *  } Finished;
         */
        return "[HandshakeType::Finished]\n"
              . "Verify Data: " . base64_encode($this->verifyData) . "\n";
    }
}





