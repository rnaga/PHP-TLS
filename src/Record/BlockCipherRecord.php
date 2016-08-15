<?php

namespace PTLS\Record;

use PTLS\Core;
use PTLS\ContentType;
use PTLS\ConnectionDuplex;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

/**
  * https://tools.ietf.org/html/rfc5246#section-6.2.3.2
  *  struct {
  *       opaque IV[SecurityParameters.record_iv_length];
  *      block-ciphered struct {
  *          opaque content[TLSCompressed.length];
  *          opaque MAC[SecurityParameters.mac_length];
  *          uint8 padding[GenericBlockCipher.padding_length];
  *          uint8 padding_length;
  *      };
  *  } GenericBlockCipher;
 */
class BlockCipherRecord extends Record
{
    const MAX_CIPHER_LENGTH = 18432; // 2^14 + 2048

    private $seq;
    private $encPayload;
    private $encLength;

    public function __construct(ConnectionDuplex $conn)
    {
        parent::__construct($conn);
        $this->maxLength = self::MAX_CIPHER_LENGTH;
    }

    /**
     * @Override
     */
    public function get($property, $default = null)
    {
        if( $property == 'length' )
        {
            return 5 + $this->encLength;
        }

        return parent::get($property);
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
        $ivLen     = $cipherSuite->getIVLen(); 
        $macLen    = $cipherSuite->getMACLen(); 

        // Copy payload over to encPayload
        $this->encPayload = $this->payload;
        $this->encLength  = $this->length;

        $IV = substr($this->encPayload, 0, $ivLen);
        
        $data = $cipherSuite->blockDecrypt($this->encPayload, $sharedKey, $IV);
 
        // If the decryption fails, a fatal bad_record_mac alert MUST be generated
        if( false === $data )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), "Cipher block decryption failed");

        // padding length - https://tools.ietf.org/html/rfc5246#section-6.2.3.2
        $paddingLength = Core::_unpack('C', $data[strlen($data)-1]);

        // Re-set the length
        $this->length = strlen($data) - $ivLen - $macLen  - $paddingLength - 1;

        // Set Payload
        $this->payload = $payload = substr($data, $ivLen, $this->length);

        if( strlen($this->payload) != $this->length )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), "Invalid block cipher length");

        // MAC to verify
        $MAC  = substr($data, $ivLen + $this->length, $macLen);
        $MAC2 = $this->calculateMAC();

        if( $MAC != $MAC2 )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), 
                "Mismatch MAC Record " . base64_encode($MAC) . "<=>" . base64_encode($MAC2));

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

        $sharedKey = $conn->Key;
        $ivLen     = $cipherSuite->getIVLen(); 
        $macLen    = $cipherSuite->getMACLen(); 

        $MAC = $this->calculateMAC();

        $IV = Core::getRandom($ivLen);

        $data = $this->payload . $MAC;

        // Calculate and append padding
        $fpd = function($l, $bz){
            return (($l+$bz) - ($l%$bz)) - $l;
        };

        $paddingLength = $fpd( strlen($this->payload . $MAC) + 1, $ivLen);

        $data .= Core::_pack('C', $paddingLength);

        $encData = $cipherSuite->blockEncrypt($data, $sharedKey, $IV);

        if( false === $encData )
            throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), "Cipher block encryption failed");

        $encData = $IV . $encData;

        $this->incrementSeq();

        if( $this->contentType == ContentType::HANDSHAKE )
            $core->countHandshakeMessages($this->payload);

        $this->set('payload', $encData );

        return parent::decode();
    }

    private function incrementSeq()
    {
        if( is_null( $this->seq ) )
        {
            $this->seq = $this->getZeroSeq();
        }

        for( $i = 7; $i >= 0; $i--)
        {
            $num = Core::_unpack('C', $this->seq[$i]) + 1;
            $this->seq[$i] = Core::_pack('C', $num );

            if( $num%256 > 0 ) break;
        }
    }

    private static function getZeroSeq()
    {
        $seq = [];
        for($i = 0; $i < 8; $i++)
            $seq[$i] = Core::_pack('C', 0);

        return $seq;
    }

    public function calculateMAC()
    {
        $conn = $this->conn;
        $core  = $conn->getCore();
        $cipherSuite = $core->cipherSuite;

        list($vMajor, $vMinor) = $core->getVersion();

        if( is_null( $this->seq ) )
        {
            $this->seq = self::getZeroSeq();
        }

        $secretMAC = $conn->MAC;

        $contentType = Core::_pack( 'C', $this->contentType );
        $major = Core::_pack( 'C', $vMajor );
        $minor = Core::_pack( 'C', $vMinor );

        $length = Core::_pack('n', strlen($this->payload));

        /*
         * https://tools.ietf.org/html/rfc5246#section-6.2.3.1
         *
         * The MAC is generated as:
         *
         * MAC(MAC_write_key, seq_num +
         *                    TLSCompressed.type +
         *                    TLSCompressed.version +
         *                    TLSCompressed.length +
         *                    TLSCompressed.fragment);
         */
        $concat = implode('', $this->seq )
                . $contentType
                . $major
                . $minor
                . $length
                . $this->payload;

        //$macStr = $cipherSuite->hashHmac($concat, $secretMAC, false );
        $mac = $cipherSuite->hashHmac($concat, $secretMAC );

        return $mac;

    }

}


