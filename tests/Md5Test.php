<?php

namespace Pop\Crypt\Test;

use Pop\Crypt\Md5;

class Md5Test extends \PHPUnit_Framework_TestCase
{

    public function testConstructor()
    {
        $md5 = new Md5();
        $this->assertInstanceOf('Pop\Crypt\Md5', $md5);
    }

    public function testCreateAndVerify()
    {
        $password = '12password34';
        $md5 = new Md5();
        $hash = $md5->create($password);
        $this->assertTrue($md5->verify($password, $hash));
    }

    public function testCreateAndVerifyCustomSalt()
    {
        $password = '12password34';
        $md5 = new Md5('MySalt');
        $hash = $md5->create($password);
        $this->assertTrue($md5->verify($password, $hash));
    }

}