<?php

namespace Www\Rsa;


use Exception;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

class Ras
{


    /**
     * 私钥文本
     * @var string
     */
    private string $privateKey_String;

    /**
     * 公钥文本
     * @var string
     */
    private string $publicKey_String;

    /**
     * 初始化
     * @param string $privateKey
     * @param string $publicKey
     */
    public function __construct(string $privateKey = '', string $publicKey = '')
    {
        if($privateKey){
            $this->privateKey_String = $privateKey;
        }
        if($publicKey){
            $this->publicKey_String = $publicKey;
        }
    }

    /**
     * 设置公钥
     * @param string $publicKey
     * @return void
     */
    public function set_publicKey(string $publicKey): void
    {
        $this->publicKey_String = $publicKey;
    }

    /**
     * 设置私钥
     * @param string $privateKey
     * @return void
     */
    public function set_privateKey(string $privateKey): void
    {
        $this->privateKey_String = $privateKey;

    }



    /**
     * 生产公钥和私钥文本
     * @param int $bits
     * @return array
     */
    public function createKey(int $bits = 4096): array
    {
        $privateKey = RSA::createKey($bits);
        $keyContent = $privateKey->toString('PKCS1'); // PKCS1 格式
        $PublicKey = $privateKey->getPublicKey();
        $publicKey = $PublicKey->toString('PKCS1');
        $Data = [];
        $Data['privateKey_string'] = $keyContent;
        $Data['publicKey_string'] = $publicKey;
        return $Data;
    }

    /**
     * RAS公钥加密
     * @param string $message
     * @param bool $is_verify
     * @return mixed
     * @throws Exception
     */
    public function encrypt(string $message = '12134567898',bool $is_verify = true): mixed
    {
        $publicKey = PublicKeyLoader::load($this->publicKey_String);
        // 要加密的消息
        $encrypted = $publicKey->encrypt($message);
        $encrypted = base64_encode($encrypted);
        if($is_verify){
            $this->verify($message,$encrypted);
        }
        // 输出加密后的消息（Base64 编码，便于阅读）
        return  $encrypted;
    }


    /**
     * Ras私钥解密
     * @param string $encrypted_text
     * @return mixed
     */
    public function decrypt(string $encrypted_text): mixed
    {
        $encrypted = base64_decode($encrypted_text); // 替换为实际加密后的密文
        $privateKey = PublicKeyLoader::load($this->privateKey_String);
        return $privateKey->decrypt($encrypted);

    }

    /**
     * 加密后对结果进行验证
     * @param string $original //   原文
     * @param string $encrypted //  密文
     * @return void
     * @throws Exception
     */
    public function verify(string $original, string $encrypted): void
    {
       $Decrypt_text = $this->decrypt($encrypted);
       if($Decrypt_text !== $original){
           throw new Exception('加密验证失败');
       }
    }









}
