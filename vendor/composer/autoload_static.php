<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit58d1c39165d8635e4e15e9068eb2c93d
{
    public static $prefixLengthsPsr4 = array (
        'A' => 
        array (
            'Alura\\Mvc\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Alura\\Mvc\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit58d1c39165d8635e4e15e9068eb2c93d::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit58d1c39165d8635e4e15e9068eb2c93d::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit58d1c39165d8635e4e15e9068eb2c93d::$classMap;

        }, null, ClassLoader::class);
    }
}
