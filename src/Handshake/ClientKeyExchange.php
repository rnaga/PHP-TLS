<?php

namespace PTLS\Handshake;

use PTLS\Core;
use PTLS\X509;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class ClientKeyExchange extends HandshakeAbstract
{
    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    private function setKeys($preMaster, $connServer, $connClient)
    {
        $core = $this->core;
        $prf = $core->prf;

        // https://tools.ietf.org/html/rfc5246#section-8.1
        // Get a master secret from premaster
        $clientRandom = $connClient->random;
        $serverRandom = $connServer->random;

        $masterSecret = $prf->getMaster($preMaster, $clientRandom, $serverRandom);
        $secretKeys   = $prf->getKeys($masterSecret, $clientRandom, $serverRandom);

        $core->setMasterSecret($masterSecret);

        // Set Secret keys
        $connClient->setSecretKeys($secretKeys['client']);
        $connServer->setSecretKeys($secretKeys['server']);
    }

    public function encode($data)
    {
        $core = $this->core;
        $extensions = $core->extensions;

        // Client
        $connIn  = $core->getInDuplex();

        // Server
        $connOut = $core->getOutDuplex();

        $data = $this->encodeHeader($data);

        // ECDHE
        if( $core->cipherSuite->isECDHEEnabled() )
        {
            $publicKeyLen = Core::_unpack( 'C', $data[0] );
            $publicKey    = substr($data, 1, $publicKeyLen );

            $preMaster = $extensions->call('Curve', 'calculatePreMaster', null, $publicKey);
        }
        // RSA
        else
        {
            // https://tools.ietf.org/html/rfc5246#section-7.4.7.1
            // Get a Premaster Secret
            $preMasterLen = Core::_unpack( 'n', $data[0] . $data[1] );
    
            $encPreMaster = substr($data, 2, $preMasterLen );
    
            $privateKey = $core->getConfig('private_key');
            openssl_private_decrypt($encPreMaster, $preMaster, $privateKey);
    
            $vMajor = Core::_unpack('C', $preMaster[0]);
            $vMinor = Core::_unpack('C', $preMaster[1]);

            list($vMajor2, $vMinor2) = $core->getVersion();

            if( $vMajor != $vMajor2 || $vMinor != $vMinor )
                throw new TLSAlertException(Alert::create(Alert::BAD_RECORD_MAC), 
                    "Invalid protocol version in PreMaster $vMajor <=> $vMajor2, $vMinor <=> $vMinor2");
        }

        $this->setKeys($preMaster, $connOut, $connIn);
    }

    public function decode()
    {
        $core = $this->core;

        list($vMajor, $vMinor) = $core->getVersion();

        // Client
        $connOut = $core->getOutDuplex();

        // Server
        $connIn = $core->getInDuplex();

        // ECDHE
        if( $core->cipherSuite->isECDHEEnabled() )
        {
            $extensions = $core->extensions;
            $data = $extensions->call('Curve', 'decodeClientKeyExchange', '');

            $preMaster = $extensions->call('Curve', 'getPremaster', null);
        }
        // RSA
        else
        {
            $preMaster = Core::_pack('C', $vMajor)
                       . Core::_pack('C', $vMinor)
                       . Core::getRandom(46);
    
            $crtDers = $core->getCrtDers();
            $publicKey = X509::getPublicKey($crtDers);

            openssl_public_encrypt($preMaster, $encPreMaster, $publicKey);
    
            $data  = Core::_pack('n', strlen($encPreMaster) ) 
                   . $encPreMaster;

        }

        // Set Master Secret, IV and MAC
        $this->setKeys($preMaster, $connIn, $connOut);

        $this->msgType = HandshakeType::CLIENT_KEY_EXCHANGE;
        $this->length = strlen($data);

        return $this->getBinHeader() . $data;
    }

    public function debugInfo()
    {
        $connOut = $core->getOutDuplex();
        $connIn  = $core->getInDuplex();

        foreach(['OUT' => $connOut, 'IN' => $connIn] as $key => $conn )
        {
            $arr[$key] = [
                'Random'        => base64_encode($conn->random),
                'CipherChanged' => (($conn->isCipherChanged) ? 'True' : 'False' ),
                'Key'           => ('MAC:       ' . base64_encode($connOut->MAC)
                                .  'IV:        ' . base64_encode($connOut->IV)
                                .  'MasterKEY: ' . base64_encode($connOut->Key)),
            ];
        }

        $output = 'IN:  ' . explode("\n", $arr['IN']) . "\n"
                . 'OUT: ' . explode("\n", $arr['OUT']) . "\n";

        return "[HandshakeType::ClientKeyExchange]\n"
             . "Lengh:                   " . $this->length . "\n"
             . $output;
    }

}




