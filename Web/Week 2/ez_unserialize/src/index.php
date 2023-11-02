<?php

show_source(__FILE__);

class Cache {
    public $key;
    public $value;
    public $expired;
    public $helper;

    public function __construct($key, $value, $helper) {
        $this->key = $key;
        $this->value = $value;
        $this->helper = $helper;

        $this->expired = False;
    }

    public function __wakeup() {
        $this->expired = False;
    }

    public function expired() {
        if ($this->expired) {
            $this->helper->clean($this->key);
            return True;
        } else {
            return False;
        }
    }
}

class Storage {
    public $store;

    public function __construct() {
        $this->store = array();
    }
    
    public function __set($name, $value) {
        if (!$this->store) {
            $this->store = array();
        }

        if (!$value->expired()) {
            $this->store[$name] = $value;
        }
    }

    public function __get($name) {
        return $this->data[$name];
    }
}

class Helper {
    public $funcs;

    public function __construct($funcs) {
        $this->funcs = $funcs;
    }

    public function __call($name, $args) {
        $this->funcs[$name](...$args);
    }
}

class DataObject {
    public $storage;
    public $data;

    public function __destruct() {
        foreach ($this->data as $key => $value) {
            $this->storage->$key = $value;
        }
    }
}

if (isset($_GET['u'])) {
    unserialize($_GET['u']);
}
?>