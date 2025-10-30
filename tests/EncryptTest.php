<?php

namespace Pop\Crypt\Test;

use PHPUnit\Framework\TestCase;

class EncryptTest extends TestCase
{

    public function testConstructor()
    {
        $encrypt = 'Encrypt';
        $this->assertIsString($encrypt);
    }

}
