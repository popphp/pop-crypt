<?php

namespace Pop\Crypt\Test;

use Pop\Crypt\Crypt;

class CryptTest extends \PHPUnit_Framework_TestCase
{

    public function testConstructor()
    {
        $crypt = new Crypt('MySalt');
        $this->assertInstanceOf('Pop\Crypt\Crypt', $crypt);
        $this->assertEquals('MySalt', $crypt->getSalt());
    }

    public function testCreateAndVerify()
    {
        $password = '12password34';
        $crypt = new Crypt('MySalt');
        $hash = $crypt->create($password);
        $this->assertTrue($crypt->verify($password, $hash));
    }

}