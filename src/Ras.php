<?php

namespace Www\Rsa;


use Exception;
use phpseclib3\Crypt\Hash;
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
        }else{
            $this->privateKey_String = Config::$privateKey;
        }
        if($publicKey){
            $this->publicKey_String = $publicKey;
        }else{
            $this->publicKey_String = Config::$publicKey;
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


    /**
     * 分段加密
     * @param $original_text
     * @return false|string
     */
    public function Segmented_encryption($original_text): false|string
    {
        $publicKey = PublicKeyLoader::load($this->publicKey_String);
        $keyLength = $publicKey->getLength(); // 以位为单位获得密钥长度
        $K = $keyLength >> 3;
        $Hash = new Hash();
        $hLen = $Hash->getLengthInBytes();
        $length = $K - 2 * $hLen - 2;
        if ($length <= 0) {
            return false;
        }
        var_dump($length);
        $plaintext = str_split($original_text, $length);
        $ciphertext = '';
        foreach ($plaintext as $m) {
            $ciphertext.= $publicKey->encrypt($m);
        }
        return base64_encode($ciphertext);

    }

    /**
     * 分段解密
     * @param $ciphertext
     * @return false|string
     */
    public function Segmented_decrypt($ciphertext): false|string
    {
        $PrivateKey = PublicKeyLoader::load($this->privateKey_String);
        $keyLength = $PrivateKey->getLength(); // 以位为单位获得密钥长度
        $K = $keyLength >> 3;
        $Hash = new Hash();
        $hLen = $Hash->getLengthInBytes();
        if ($K <= 0) {
            return false;
        }
        $ciphertext = base64_decode($ciphertext); // 替换为实际加密后的密文
        $ciphertext = str_split($ciphertext, $K);
        $ciphertext[count($ciphertext) - 1] = str_pad($ciphertext[count($ciphertext) - 1], $K, chr(0), STR_PAD_LEFT);
        $plaintext = '';
        foreach ($ciphertext as $c) {
            $temp = $PrivateKey->decrypt($c);
            if ($temp === false) {
                return false;
            }
            $plaintext.= $temp;
        }
        return $plaintext;
    }








}
