<?php

namespace PTLS;

use Mdanter\Ecc\Crypto\EcDH\EcDH as MdanterEcDH;;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Crypto\Key\PublicKey;

/**
 * https://tools.ietf.org/html/rfc4492#section-5.1.1
 *
 * enum {
 *    sect163k1 (1), sect163r1 (2), sect163r2 (3),
 *    sect193r1 (4), sect193r2 (5), sect233k1 (6),
 *    sect233r1 (7), sect239k1 (8), sect283k1 (9),
 *    sect283r1 (10), sect409k1 (11), sect409r1 (12),
 *    sect571k1 (13), sect571r1 (14), secp160k1 (15),
 *    secp160r1 (16), secp160r2 (17), secp192k1 (18),
 *    secp192r1 (19), secp224k1 (20), secp224r1 (21),
 *    secp256k1 (22), secp256r1 (23), secp384r1 (24),
 *    secp521r1 (25),
 *    reserved (0xFE00..0xFEFF),
 *    arbitrary_explicit_prime_curves(0xFF01),
 *    arbitrary_explicit_char2_curves(0xFF02),
 *    (0xFFFF)
 * } NamedCurve;
 *
 * ------------------------------------------
 * We support below
 * ------------------------------------------
 * self::TYPE_SECP256R1 => secp256r1 
 * self::TYPE_SECP384R1 => secp384r1
 *
 */
class EcDH
{
    const TYPE_SECP256R1 = 23;
    const TYPE_SECP384R1 = 24;

    public static $typeList = [
        self::TYPE_SECP256R1,
        self::TYPE_SECP384R1,
    ];

    private $ecdh;
    private $curve;
    private $gen;
    private $privateKey;
    private $publicKey;
    private $adapter;  
 
    public static function isSupported(int $type)
    {
        switch($type)
        {
            case self::TYPE_SECP256R1:
            case self::TYPE_SECP384R1:
                return true;
        }

        return false;
    }

    function __construct($type)
    {
        $this->type = $type;

        $this->ecdh  =
        $this->curve =
        $this->gen   =
        $this->privateKey =
        $this->publicKey  =
        $this->adapter = null;
    }

    private function getGenerator()
    {
        if( !is_null( $this->gen ) )
            return $this->gen;

        switch($this->type)
        {
            case self::TYPE_SECP256R1:
                $gen = EccFactory::getSecgCurves()->generator256r1();
                break;
            case self::TYPE_SECP384R1:
                $gen = EccFactory::getSecgCurves()->generator384r1();
                break;

            default: return null;
        }

        $this->gen = $gen;
        return $this->gen;

    }

    private function getCurve()
    {
        if( !is_null( $this->curve ) )
            return $this->curve;

        switch($this->type)
        {
            case self::TYPE_SECP256R1:
                $curve = EccFactory::getSecgCurves()->curve256r1();
                break;
            case self::TYPE_SECP384R1:
                $curve = EccFactory::getSecgCurves()->curve384r1();
                break;

            default: return null;
        }

        $this->curve = $curve;
        return $this->curve;
    }

    private function getAdapter()
    {
        if( !is_null( $this->adapter ) )
            return $this->adapter;

        $this->adapter = EccFactory::getAdapter();
        return $this->adapter;
    }

    private function getEcdh()
    {
        if( !is_null( $this->ecdh ) )
            return $this->ecdh;

        $adapter = $this->getAdapter();

        $this->ecdh = new MdanterEcDH($adapter);  
        return $this->ecdh;  
    }

    public function getPrivateKey()
    {
        if( !is_null( $this->privateKey ) )
            return $this->privateKey;

        $gen = $this->getGenerator();;

        $this->privateKey = $gen->createPrivateKey();

        return $this->privateKey;
    }

    public function createPrivateKey()
    {
        $this->getPrivateKey();
        return $this;
    }

    public function getPublicKey()
    {
        $privateKey = $this->getPrivateKey();

        $this->publicKey = $publicKey = $privateKey->getPublicKey();

        $publicPoint = $publicKey->getPoint();

        // Convert to binary - Uncompressed
        $publicKeyBin = Core::_pack('C', 0x04)
                . gmp_export($publicPoint->getX(), 1, GMP_BIG_ENDIAN)
                . gmp_export($publicPoint->getY(), 1, GMP_BIG_ENDIAN);

        return $publicKeyBin;
    }

    public function calculateSharedKey($publicKeyBin)
    {
        $length = strlen($publicKeyBin) - 1;

        if( $length % 2 != 0 )
            return;

        $half = $length/2;

        $x = substr($publicKeyBin, 1, $half);
        $gmpX = gmp_import($x, 1);

        $y = substr($publicKeyBin, $half+1);
        $gmpY = gmp_import($y, 1);

        $curve   = $this->getCurve();
        $adapter = $this->getAdapter();
        $gen     = $this->getGenerator();
        $ecdh    = $this->getEcdh();

        $point = $curve->getPoint($gmpX, $gmpY);

        $privateKey = $this->getPrivateKey();
        $publicKey  = new PublicKey($adapter, $gen, $point);

        $ecdh->setSenderKey($privateKey);
        $ecdh->setRecipientKey($publicKey);

        $sharedKey = $ecdh->calculateSharedKey();

        return gmp_export($sharedKey);
    } 
}



