<?php

namespace Pop\Crypt\Test;

use Pop\Crypt\Sha;

class ShaTest extends \PHPUnit_Framework_TestCase
{

    public function testConstructor()
    {
        $sha = new Sha();
        $this->assertInstanceOf('Pop\Crypt\Sha', $sha);
    }

    public function testSetAndGetBits256()
    {
        $sha = new Sha();
        $sha->setBits256();
        $this->assertEquals(256, $sha->getBits());
    }

    public function testSetAndGetRounds()
    {
        $sha = new Sha();
        $sha->setRounds(1000);
        $this->assertEquals(1000, $sha->getRounds());
    }

    public function testSetAndGetRoundsOutOfRange1()
    {
        $sha = new Sha();
        $sha->setRounds(100);
        $this->assertEquals(1000, $sha->getRounds());
    }

    public function testSetAndGetRoundsOutOfRange2()
    {
        $sha = new Sha();
        $sha->setRounds(10000000000);
        $this->assertEquals(999999999, $sha->getRounds());
    }

    public function testCreateAndVerify()
    {
        $password = '12password34';
        $sha = new Sha();
        $hash = $sha->create($password);
        $this->assertTrue($sha->verify($password, $hash));
    }

    public function testCreateAndVerifyCustomSalt()
    {
        $password = '12password34';
        $sha = new Sha('MySalt', 256);
        $hash = $sha->create($password);
        $this->assertTrue($sha->verify($password, $hash));
    }

}