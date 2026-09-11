<?php

$autoload = __DIR__.'/../vendor/autoload.php';
require_once is_file($autoload) ? $autoload : __DIR__.'/../../../vendor/autoload.php';
spl_autoload_register(function (string $class): void {
    $prefix = 'BasicXII\\CloudSecurity\\';
    if (str_starts_with($class, $prefix)) {
        $file = __DIR__.'/../src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
        if (is_file($file)) {
            require_once $file;
        }
    }
});
