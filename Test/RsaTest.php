<?php

namespace Www\Test;

use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\TestCase;
use Www\Rsa\AES;
use Www\Rsa\Ras;
use Www\Rsa\Tool;

class RsaTest extends TestCase
{
    public function testCreateKeyExample()
    {
        $Tool = new Tool();
        $Data = $Tool->hybrid_encryption('HI,123456');
        var_dump($Data);
        echo '解密结果:'.$Tool->hybrid_decrypt($Data);
    }
}
