<?php

namespace PTLS;

use PTLS\TLS;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class CipherSuites
{
    const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F;
    const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030;
    const TLS_RSA_WITH_AES_128_GCM_SHA256    = 0x009C;
    const TLS_RSA_WITH_AES_256_GCM_SHA384    = 0x009D;
    const TLS_RSA_WITH_AES_128_CBC_SHA       = 0x002F;
    const TLS_RSA_WITH_AES_256_CBC_SHA       = 0x0035;
    const TLS_RSA_WITH_AES_128_CBC_SHA256    = 0x003C;
    const TLS_RSA_WITH_AES_256_CBC_SHA256    = 0x003D; 
    const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013;
    const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014;    

    private static $cipherList = [
        self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =>
        ['cipher_type' => self::CIPHER_TYPE_AEAD, 'crypto_method' => 'AES-128-GCM', 'mac_len' => 0, 'iv_len' => 4, 'key_len' => 16, 'mac' => 'sha256'],

        self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =>
        ['cipher_type' => self::CIPHER_TYPE_AEAD, 'crypto_method' => 'AES-256-GCM', 'mac_len' => 0, 'iv_len' => 4, 'key_len' => 32, 'mac' => 'sha384'],

        self::TLS_RSA_WITH_AES_128_GCM_SHA256 =>
        ['cipher_type' => self::CIPHER_TYPE_AEAD, 'crypto_method' => 'AES-128-GCM', 'mac_len' => 0, 'iv_len' => 4, 'key_len' => 16, 'mac' => 'sha256'],

        self::TLS_RSA_WITH_AES_256_GCM_SHA384 =>
        ['cipher_type' => self::CIPHER_TYPE_AEAD, 'crypto_method' => 'AES-256-GCM', 'mac_len' => 0, 'iv_len' => 4, 'key_len' => 32, 'mac' => 'sha384'],

        self::TLS_RSA_WITH_AES_256_CBC_SHA =>
        ['cipher_type' => self::CIPHER_TYPE_BLOCK, 'crypto_method' => 'AES-256-CBC', 'mac_len' => 20, 'iv_len' => 16, 'key_len' => 32, 'mac' => 'sha1'],

        self::TLS_RSA_WITH_AES_128_CBC_SHA => 
        ['cipher_type' => self::CIPHER_TYPE_BLOCK, 'crypto_method' => 'AES-128-CBC', 'mac_len' => 20, 'iv_len' => 16, 'key_len' => 16, 'mac' => 'sha1'],

        self::TLS_RSA_WITH_AES_128_CBC_SHA256 =>
        ['cipher_type' => self::CIPHER_TYPE_BLOCK, 'crypto_method' => 'AES-128-CBC', 'mac_len' => 32, 'iv_len' => 16, 'key_len' => 16, 'mac' => 'sha256'],
 
        self::TLS_RSA_WITH_AES_256_CBC_SHA256 =>
        ['cipher_type' => self::CIPHER_TYPE_BLOCK, 'crypto_method' => 'AES-256-CBC', 'mac_len' => 32, 'iv_len' => 16, 'key_len' => 32, 'mac' => 'sha256'],

        self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA =>
        ['cipher_type' => self::CIPHER_TYPE_BLOCK, 'crypto_method' => 'AES-128-CBC', 'mac_len' => 20, 'iv_len' => 16, 'key_len' => 16, 'mac' => 'sha1'],

        self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA =>
        ['cipher_type' => self::CIPHER_TYPE_BLOCK, 'crypto_method' => 'AES-256-CBC', 'mac_len' => 20, 'iv_len' => 16, 'key_len' => 32, 'mac' => 'sha1'],
    ];

    public static $enabledCipherSuites = [
        self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        self::TLS_RSA_WITH_AES_256_GCM_SHA384,
        self::TLS_RSA_WITH_AES_128_GCM_SHA256,
        self::TLS_RSA_WITH_AES_256_CBC_SHA256,
        self::TLS_RSA_WITH_AES_256_CBC_SHA,
        self::TLS_RSA_WITH_AES_128_CBC_SHA256,
        self::TLS_RSA_WITH_AES_128_CBC_SHA,
    ];

    const CIPHER_TYPE_STREAM = 1;
    const CIPHER_TYPE_BLOCK  = 2;
    const CIPHER_TYPE_AEAD   = 3;

    private $macLen;
    private $ivLen;
    private $keyLen;
    private $macAlgorithm;
    private $cryptoMethod;
    private $cipherType;
    private $cipherID;

    public function __construct(array $arr)
    {
        $cipherID = $arr[0] << 8 | $arr[1];

        if( !array_key_exists($cipherID, self::$cipherList) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Failed to initiate CipherSuite. cipherID: $cipherID");

        $cipherSuite = self::$cipherList[$cipherID];

        $this->cipherID  = $cipherID;

        $this->cipherType   = $cipherSuite['cipher_type'];
        $this->ivLen        = $cipherSuite['iv_len'];
        $this->keyLen       = $cipherSuite['key_len'];
        $this->macLen       = $cipherSuite['mac_len'];
        $this->cryptoMethod = $cipherSuite['crypto_method'];
        $this->macAlgorithm = $cipherSuite['mac'];
    }

    public function isECDHEEnabled()
    {
        return self::isECDHE($this->cipherID);
    }

    public static function isGCM($cipherID)
    {
        switch($cipherID)
        {
            case self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            case self::TLS_RSA_WITH_AES_128_GCM_SHA256:
            case self::TLS_RSA_WITH_AES_256_GCM_SHA384:
                return true;
        }

        return false;
    }

    public static function isECDHE($cipherID)
    {
        switch($cipherID)
        {
            case self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            case self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            case self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                return true;
        }

        return false;
    }

    public static function pickCipherID(Core $core, array $arr)
    {
        $extensions = $core->extensions;

        foreach( $arr as $val)
        {
            list($cipher1, $cipher2) = $val;

            $cipherID = $cipher1 << 8 | $cipher2;

            if( in_array($cipherID, self::$enabledCipherSuites ) )
            {
                if( self::isECDHE($cipherID) && true !== $extensions->call('Curve', 'isEnabled', false) )
                    continue;
                else 
                    return [$cipher1, $cipher2];
            }
        } 

        return null;
    }

    public static function decodeCipherList()
    {
        $data = '';

        foreach(self::$enabledCipherSuites as $val)
        {
            $data .= Core::_pack('C', $val >> 8) . Core::_pack('C', $val & 0x00ff);
        }

        return $data;
    }

    private function getProperty($property)
    {
        if( !property_exists($this, $property) )
            return;

        return $this->$property;
    }

    public function getID()
    {
        $cipherID = $this->getProperty('cipherID');
        return [$cipherID >> 8, $cipherID & 0x00ff];
    }

    /**
     * 
     * https://tools.ietf.org/html/rfc5288 Page 2
     *
     * The Pseudo Random Function (PRF) algorithms SHALL be as follows:
     *
     *  For cipher suites ending with _SHA256, the PRF is the TLS PRF
     * [RFC5246] with SHA-256 as the hash function.
     *
     *  For cipher suites ending with _SHA384, the PRF is the TLS PRF
     * [RFC5246] with SHA-384 as the hash function.
     * 
     * This is also used by Finished message in Handshake
     */
    public function getHashAlogV33()
    {
        if( self::isGCM($this->cipherID) )
            return $this->macAlgorithm;

        return 'sha256';
    }

    public function getKeyLen()
    {
        return $this->getProperty('keyLen');
    }

    public function getIVLen()
    {
        return $this->getProperty('ivLen');
    }

    public function getMACLen()
    {
        return $this->getProperty('macLen');
    }

    public function getCipherType()
    {
        return $this->getProperty('cipherType');
    }

    public function blockDecrypt($encPayload, $sharedKey, $IV)
    {
        $data = openssl_decrypt($encPayload, $this->cryptoMethod, $sharedKey, OPENSSL_ZERO_PADDING|OPENSSL_RAW_DATA, $IV);
        return $data;
    }

    public function blockEncrypt($payload, $sharedKey, $IV)
    {
        $encData = openssl_encrypt($payload, $this->cryptoMethod, $sharedKey, OPENSSL_RAW_DATA, $IV);
        return $encData;
    }

    public function hashHmac($data, $secretMac, $binary = true)
    {
        return hash_hmac($this->macAlgorithm, $data, $secretMac, $binary );
    }

    public function gcmEncrypt($payload, $sharedKey, $nonce, $aad)
    {
        return AEADGcm::encrypt($payload, $sharedKey, $nonce, $aad);
    }

    public function gcmDecrypt($encData, $sharedKey, $nonce, $aad)
    {
        return AEADGcm::decrypt($encData, $sharedKey, $nonce, $aad);
    }

    public function debugInfo()
    {
        $class = new \ReflectionClass(__CLASS__);
        $constants = array_flip($class->getConstants());

        $outputs[] = 'Cipher ID:     ' . $constants[$this->cipherID];
        $outputs[] = 'MAC Length:    ' . $this->macLen;
        $outputs[] = 'IV Length:     ' . $this->ivLen;
        $outputs[] = 'MAC Algorithm: ' . $this->macAlgorithm;

        $r = "[CipherSuite]\n"
           . implode("\n", $outputs);

        return $r;
    }

}



