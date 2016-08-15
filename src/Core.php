<?php

namespace PTLS;

use PTLS\Buffer;
use PTLS\Content\ClientContent;
use PTLS\Content\ServerContent;
use PTLS\ConnectionDuplex;
use PTLS\Extensions\TLSExtensions;
use PTLS\X509;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class Core
{
    public $isServer;

    /**
     * True when handshake is done and connection is established
     */
    public $isHandshaked;


    /**
     * True when alert message is received
     */
    public $isClosed;

    /**
     *  https://tools.ietf.org/html/rfc5246#appendix-A.5
     *  The Cipher Suite
     */
    public $cipherSuite;

    /**
     * https://tools.ietf.org/html/rfc5246#section-5
     *  HMAC and the Pseudorandom Function
     */
    public $prf;

    /**
     * https://tools.ietf.org/html/rfc5246#section-7.4.1.4
     */
    public $extensions;

    /**
     * https://tools.ietf.org/html/rfc5246#section-6.2.1
     *
     * Content Encoder
     */
    public $content;

    private $config;

    /**
     * https://tools.ietf.org/html/rfc5246#appendix-A.1
     *
     * TLS Protocol Version
     */
    private $vMajor = null, $vMinor = null;

    /**
     *  Set default TLS version as 1.2
     */
    private $vMajorDefault = 3, $vMinorDefault = 3;
    private $protocolVersion;

    /**
     * https://tools.ietf.org/html/rfc5246#section-7.4.7
     *
     * Client Key Exchange Message
     */
    private $masterSecret;

    /**
     * https://tools.ietf.org/html/rfc5246#section-7.4.9
     * All of the data from all messages in this handshake (not
     *     including any HelloRequest messages) up to, but not including,
     *     this message.
     *
     * https://tools.ietf.org/html/rfc5246#section-7.4.1.1
     * This message MUST NOT be included in the message hashes that are
     * maintained throughout the handshake and used in the Finished messages
     * and the certificate verify message 
     */
    private $handshakeMessages;

    /**
     * https://tools.ietf.org/html/rfc5246#section-7 page 26
     * session identifier
     *   An arbitrary byte sequence chosen by the server to identify an
     *  active or resumable session state.
     */
    private $sessionID;

    /**
     * No compression method for this library(null)
     */
    private $compressionMethod;

    /**
     * Certificates used by a server
     */
    private $crtDers;

    private $server; // ConnectionDuplex
    private $client; // ConnectionDuplex

    private $bufferIn, $bufferOut; // Buffer

    function __construct(bool $isServer, Config $config)
    {
        $this->config = $config;

        $this->isHandshaked = false;
        $this->isClosed = false;

        $this->isServer = $isServer;

        $this->server = new ConnectionDuplex($this);
        $this->client = new ConnectionDuplex($this);

        $this->handshakeMessages = '';

        $this->bufferIn  = new Buffer();
        $this->bufferOut = new Buffer();

        $this->extensions = new TLSExtensions($this);

        // Compression Method - uncompressed
        $this->compressionMethod = 0;

        // Prf
        $this->prf = new Prf($this);

        $this->handshakeMessages = [];

        if( $isServer )
        {
            $this->crtDers = $this->config->get('crt_ders');
            $this->content = new ServerContent($this);
        }
        else // Client
        {
            $this->content = new ClientContent($this);
            $this->setVersion(3, $config->get('version', $this->vMinorDefault));
        }
    }

    /**
     * Getter and Setter
     */
    public function __call(string $name, array $args)
    {
        if( strlen($name) < 3 ) 
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Core::$name too short");

        $properties = ['bufferIn', 'bufferOut', 'sessionID', 'compressionMethod', 'masterSecret', 'crtDers'];

        $getOrSet = substr($name, 0, 3);

        if( $getOrSet != 'get' && $getOrSet != 'set' )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Core::$name not exist");

        $property = substr($name, 3);
        $property[0] = strtolower($property[0]);

        if( !in_array($property, $properties) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Core::$property not exist");

        // Getter
        if( $getOrSet == 'get' )
            return $this->$property;

        if( !isset( $args[0] ) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "No args set for Core::$property");

        // Setter    
        $this->$property = $args[0]; 
    }

    public function getOutDuplex()
    {
        return ($this->isServer ) ? $this->server : $this->client;
    }

    public function getInDuplex()
    {
        return ($this->isServer ) ? $this->client : $this->server;
    }

    public function getProtocolVersion()
    {
        return $this->protocolVersion;
    }

    public function getVersion()
    {
        if( $this->vMajor == 0 || $this->vMinor == 0 )
            return [$this->vMajorDefault, $this->vMinorDefault];

        return [$this->vMajor, $this->vMinor];
    }

    public function setVersion($vMajor, $vMinor)
    {
        if( $vMajor != 3 || ( $vMinor > 3 && $vMinor < 2 ) )
            throw new TLSAlertException(Alert::create(Alert::PROTOCOL_VERSION), "Unsupported Protocol $vMajor:$vMinor");

        if( !is_null( $this->protocolVersion ) )
            return;

        $this->vMajor = $vMajor;
        $this->vMinor = $vMinor;

        // TLS1.2
        if( $this->vMinor == 3 )
            $this->protocolVersion = 32;
        // TLS1.1
        else
            $this->protocolVersion = 31;
    }

    /**
     * All Handshake messages must be recorded
     */
    public function countHandshakeMessages($msg)
    {
        if( $this->isHandshaked )
            return;

        $this->handshakeMessages[] = $msg;
    }

    public function getHandshakeMessages($sub = 0)
    {
        if( $sub != 0 )
            $msg = implode('', array_slice($this->handshakeMessages, 0, count($this->handshakeMessages) - $sub));
        else
            $msg = implode('', $this->handshakeMessages);

        return $msg;
    }

    public function getConfig($key)
    {
        return $this->config->get($key);
    }

    /**
     *  Generate client/server random, IV, PreMaster for RSA Key Exchange
     */
    public static function getRandom($length)
    {
        $random = openssl_random_pseudo_bytes($length, $strong);

        if( true !== $strong )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Random byte not strong");

        return $random;
    }

    public static function _unpack( $f, $d )
    {
        $r = unpack( $f, $d );

        if( !is_array($r) || !isset($r[1]) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "unpack failed. format: $f, data: $d");

        return $r[1];
    }

    public static function _pack( $f, $d )
    {
        return pack( $f, $d );
    }
}






