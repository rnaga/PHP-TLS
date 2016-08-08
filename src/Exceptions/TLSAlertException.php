<?php

namespace PTLS\Exceptions;

use PTLS\Core;
use PTLS\Content\Alert;
use PTLS\ContentType;

class TLSAlertException extends \Exception
{
    private $alert;
    private $output;

    function __construct(Alert $alert, string $message)
    {
        $this->output = null;
        $this->alert = $alert;
        $message = $this->alert->toString() . " " . $message;
        parent::__construct($message, $alert->getDescCode());
    }

    public function setOutput(Core $core)
    {
        $alert = $this->alert;

        if( $alert->fromPeer() ) return;

        $recordOut = $core->getOutDuplex()->getRecord();

        $payload = $alert->decode();

        $this->output = $recordOut->set('contentType', ContentType::ALERT)
                         ->set('payload', $payload )
                         ->decode();
    }

    public function decode()
    {
        return $this->output;
    }
}


