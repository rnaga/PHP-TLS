<?php

namespace PTLS\Record;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\ConnectionDuplex;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

/**
 * https://tools.ietf.org/html/rfc5246#section-6.2.3.3
 *
 *    struct {
 *       opaque nonce_explicit[SecurityParameters.record_iv_length];
 *       aead-ciphered struct {
 *           opaque content[TLSCompressed.length];
 *       };
 *    } GenericAEADCipher;
 *
 * Supporting GCM
 */
class AEADCipherRecord extends CipherRecordAbstract
{
    const nonceExplicitLen = 8;

    public function __construct(ConnectionDuplex $conn)
    {
        parent::__construct($conn);
    }

    /**
     * @Override
     */
    protected function encodeContent()
    {
        $payload = $this->payload;

        $conn = $this->conn;
        $core  = $conn->getCore();

        $cipherSuite = $core->cipherSuite;
        $sharedKey = $conn->Key;

        $nonceImplicit = $conn->IV;

        // 16 => tag length
        $gcmHeaderLen  = self::nonceExplicitLen + 16;
        $rawPayloadLen = strlen($this->payload);

        if( $rawPayloadLen < $gcmHeaderLen )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), "GCM payload too short");

        $nonceExplicit = substr($this->payload, 0, self::nonceExplicitLen);

        $aad = $this->getAAD($rawPayloadLen - $gcmHeaderLen);

        // Copy payload over to encPayload
        $this->encPayload = $this->payload;
        $this->encLength  = $this->length;

        $nonce   = $nonceImplicit . $nonceExplicit; 
        $encData = substr($this->encPayload, self::nonceExplicitLen); 

        $data = $cipherSuite->gcmDecrypt($encData, $sharedKey, $nonce, $aad);

        // If the decryption fails, a fatal bad_record_mac alert MUST be generated
        if( false === $data )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), "Cipher gcm decryption failed");

        // Re-set the length
        $this->length = strlen($data);

        // Set Payload
        $this->payload = $payload = substr($data, 0, $this->length); 

        $this->incrementSeq();

        $content = $core->content;

        $content->encodeContent($this->contentType, $this->payload, $this);
    }

    /**
     * @Override
     */
    public function decode()
    {
        $conn = $this->conn;
        $core  = $conn->getCore();

        $cipherSuite = $core->cipherSuite;

        $nonceImplicit = $conn->IV; // 4 bytes
        $sharedKey = $conn->Key;

        $aad = $this->getAAD($this->length);

        $nonceExplicit = $this->getSeq(); // 8 bytes

        /*
         *  https://tools.ietf.org/html/rfc5288 page 2
         *
         *  struct {
         *       opaque salt[4];
         *       opaque nonce_explicit[8];
         *  } GCMNonce;
         */
        $nonce = $nonceImplicit . $nonceExplicit; 

        $encData = $cipherSuite->gcmEncrypt($this->payload, $sharedKey, $nonce, $aad); 

        if( false === $encData )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), "Cipher gcm encryption failed");

        $this->incrementSeq();

        if( $this->contentType == ContentType::HANDSHAKE )
            $core->countHandshakeMessages($this->payload);

        $payload = $nonceExplicit . $encData;

        $this->set('payload', $payload );

        return parent::decode();
    }

    /**
     * Additional Authentication Data
     */ 
    public function getAAD($length)
    {
        $conn = $this->conn;
        $core  = $conn->getCore();
        $cipherSuite = $core->cipherSuite;

        list($vMajor, $vMinor) = $core->getVersion();

        if( is_null( $this->seq ) )
        {
            $this->seq = self::getZeroSeq();
        }

        $contentType = Core::_pack( 'C', $this->contentType );
        $major = Core::_pack( 'C', $vMajor );
        $minor = Core::_pack( 'C', $vMinor );

        $length = Core::_pack('n', $length);

        /*
         * https://tools.ietf.org/html/rfc5246#section-6.2.3.3
         *
         *  additional_data = seq_num + TLSCompressed.type +
         *               TLSCompressed.version + TLSCompressed.length;
         *
         */
        $concat = implode('', $this->seq )
                . $contentType
                . $major
                . $minor
                . $length;

        return $concat;
    }

}


