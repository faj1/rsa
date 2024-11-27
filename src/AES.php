<?php

namespace Www\Rsa;

use Exception;
use Random\RandomException;

class AES
{

    public string $key;
    public string $iv;


    /**
     * 初始化
     * @param string $key
     * @param string $iv
     * @throws RandomException
     */
    public function __construct(string $key = '', string $iv = '')
    {
        if($key){
            $this->key = $key;
        }else{
            $this->key = $this->getKey();
        }
        if($iv){
            $this->iv = $iv;
        }else{
            $this->iv = $this->generateRandomString(16);
        }

    }


    /**
     * Aes加密
     * @param string $plaintext
     * @param bool $is_verify
     * @return false|string
     * @throws Exception
     */
    public function aes_encrypt(string $plaintext,bool $is_verify = true): false|string
    {
        // AES-256-CBC 加密

        $cipher_text = openssl_encrypt($plaintext, 'AES-256-CBC', $this->key, 0, $this->iv);
        if($is_verify){
           if ($this->aes_decrypt($cipher_text) != $plaintext){
               throw new Exception('加密验证失败');
           };
        }
        return openssl_encrypt($plaintext, 'AES-256-CBC', $this->key, 0, $this->iv);
    }

    /**
     * Aes解密
     * @param $ciphertext
     * @return false|string
     */
    public function aes_decrypt($ciphertext): false|string
    {
        // AES-256-CBC 解密
        return openssl_decrypt($ciphertext, 'AES-256-CBC',$this->key, 0, $this->iv);
    }


    /**
     * 生产随机的字符串作为密码
     * @param $length
     * @return string
     * @throws RandomException
     */
    public  function generateRandomString($length = 32): string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }
        return $randomString;
    }


    /**
     * 生产密码
     * @return string
     * @throws RandomException
     */
    public function getKey()
    {
        return md5(md5(md5($this->generateRandomString(32))));
    }


}
