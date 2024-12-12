<?php

namespace Www\Test;

use PHPUnit\Framework\TestCase;
use Www\Rsa\Ras;
use Www\Rsa\Tool;

class RsaTest extends TestCase
{
    public function testCreateKeyExample()
    {
        $Ras = new Ras();
        $createKey = $Ras->createKey(4096);
        $Tool = new Tool();
        $Data = $Tool->hybrid_encryption('HI,123456下从 撒大大',$createKey['privateKey_string'],$createKey['publicKey_string']);
        echo "加密内容:".json_encode($Data).PHP_EOL;
        echo '解密结果:'.$Tool->hybrid_decrypt($Data,$createKey['privateKey_string'],$createKey['publicKey_string'] );
        $this->assertTrue(true, 'Code executed successfully without exceptions.');
    }
}
