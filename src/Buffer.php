<?php

namespace PTLS;

/**
 * Simple buffering
 */
class Buffer
{
    private $buffer;

    public function set($data)
    {
        $this->buffer = $data;
        return $this;
    }

    public function append($data)
    {
        $this->buffer .= $data;
        return $this;
    }

    public function flush()
    {
        $data = $this->buffer;
        $this->buffer = null;
        return $data;
    }

    public function get()
    {
        return $this->buffer;
    }

    public function length()
    {
        return strlen($this->buffer);
    }
}

