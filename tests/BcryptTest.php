<?php

namespace Pop\Crypt\Test;

use Pop\Crypt\Bcrypt;

class BcryptTest extends \PHPUnit_Framework_TestCase
{

    public function testConstructor()
    {
        $bcrypt = new Bcrypt();
        $this->assertInstanceOf('Pop\Crypt\Bcrypt', $bcrypt);
    }

    public function testSetAndGetCost()
    {
        $bcrypt = new Bcrypt();
        $bcrypt->setCost('09');
        $this->assertEquals('09', $bcrypt->getCost());
    }

    public function testSetAndGetCostOutOfRange1()
    {
        $bcrypt = new Bcrypt();
        $bcrypt->setCost('01');
        $this->assertEquals('04', $bcrypt->getCost());
    }

    public function testSetAndGetCostOutOfRange2()
    {
        $bcrypt = new Bcrypt();
        $bcrypt->setCost('41');
        $this->assertEquals('31', $bcrypt->getCost());
    }

    public function testSetAndGetPrefix()
    {
        $bcrypt = new Bcrypt();
        $bcrypt->setPrefix('$2a$');
        $this->assertEquals('$2a$', $bcrypt->getPrefix());
    }

    public function testSetAndGetPrefixOutOfRange()
    {
        $bcrypt = new Bcrypt();
        $bcrypt->setPrefix('$2aaa$');
        $this->assertEquals('$2y$', $bcrypt->getPrefix());
    }

    public function testCreateAndVerify()
    {
        $password = '12password34';
        $bcrypt = new Bcrypt();
        $hash = $bcrypt->create($password);
        $this->assertTrue($bcrypt->verify($password, $hash));
    }

}