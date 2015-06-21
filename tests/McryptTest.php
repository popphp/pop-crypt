<?php

namespace Pop\Crypt\Test;

use Pop\Crypt\Mcrypt;

class McryptTest extends \PHPUnit_Framework_TestCase
{


    public function testConstructor()
    {
        $mcrypt = new Mcrypt('MySalt');
        $this->assertInstanceOf('Pop\Crypt\Mcrypt', $mcrypt);
        $this->assertEquals('MySalt', $mcrypt->getSalt());
        $this->assertEquals(MCRYPT_RIJNDAEL_256, $mcrypt->getCipher());
        $this->assertEquals(MCRYPT_MODE_CBC, $mcrypt->getMode());
        $this->assertEquals(MCRYPT_RAND, $mcrypt->getSource());

    }

    public function testCreateAndVerify()
    {
        $password = '12password34';
        $mcrypt   = new Mcrypt('MySalt');
        $hash     = $mcrypt->create($password);
        $this->assertTrue($mcrypt->verify($password, $hash));
        $this->assertNotNull($mcrypt->getIv());
        $this->assertGreaterThan(0, $mcrypt->getIvSize());
    }

    public function testDecrypt()
    {
        $password = '12password34';
        $mcrypt   = new Mcrypt();
        $hash     = $mcrypt->create($password);
        $this->assertTrue($mcrypt->verify($password, $hash));
        $this->assertEquals('12password34', $mcrypt->decrypt($hash));
    }

    public function testDecryptWithSalt()
    {
        $password = '12password34';
        $mcrypt   = new Mcrypt('MySalt');
        $hash     = $mcrypt->create($password);
        $this->assertTrue($mcrypt->verify($password, $hash));
        $this->assertEquals('12password34', $mcrypt->decrypt($hash));
    }

}