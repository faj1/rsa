<?php

namespace Www\Rsa;

use Exception;
use Random\RandomException;

class Tool
{

    /**
     *
     * @param string $original_Text //待加密文本
     * @param string $privateKey   //RSA私钥
     * @param string $publicKey   //RAS公钥
     * @param bool $is_verify     //加密是否验证
     * @throws Exception
     */
    public function hybrid_encryption(string $original_Text, string $privateKey = '', string $publicKey = '', bool $is_verify = true): array
    {
        if(!$privateKey){
            $privateKey = Config::$privateKey;
        }
        if(!$publicKey){
            $publicKey = Config::$publicKey;
        }
        $Ras = new Ras($privateKey, $publicKey);
        $AES = new AES();
        $cipher_text = $AES->aes_encrypt($original_Text,$is_verify);
        $Data = [];
        $Data['cipher_text'] = $cipher_text;
        $Data['key'] = $Ras->encrypt($AES->key,$is_verify);
        $Data['iv'] = $AES->iv;
        return $Data;
    }


    /**
     * 混合解密
     * @param array $Data
     * @param string $privateKey
     * @param string $publicKey
     * @return false|string
     * @throws RandomException
     */
    public function hybrid_decrypt(array $Data, string $privateKey = '', string $publicKey = ''): false|string
    {
        if(!$privateKey){
            $privateKey = Config::$privateKey;
        }
        if(!$publicKey){
            $publicKey = Config::$publicKey;
        }
        $Ras = new Ras($privateKey, $publicKey);
        $Key = $Ras->decrypt($Data['key']);
        $AES = new AES($Key,$Data['iv']);
        return $AES->aes_decrypt($Data['cipher_text']);
    }



}
