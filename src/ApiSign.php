<?php

namespace Www\Rsa;

class ApiSign
{
    // 密钥
    private string $secretKey;

    // 默认哈希算法
    private string $hashAlgorithm;

    // 签名有效期（秒）
    private int $signatureExpiry;

    // 是否调试模式
    private bool $debug;

    /**
     * 构造函数
     *
     * @param string $secretKey 密钥
     * @param string $hashAlgorithm 哈希算法，默认是 sha256
     * @param int $signatureExpiry 签名有效期（秒），默认 300 秒（5 分钟）
     * @param bool $debug 是否开启调试模式，默认关闭
     */
    public function __construct(string $secretKey, string $hashAlgorithm = 'sha256', int $signatureExpiry = 300, bool $debug = false)
    {
        $this->secretKey = $secretKey;
        $this->hashAlgorithm = $hashAlgorithm;
        $this->signatureExpiry = $signatureExpiry;
        $this->debug = $debug;
    }

    /**
     * 生成签名
     *
     * @param array $params 请求参数
     * @return string 生成的签名
     */
    public function generateSignature(array $params): string
    {
        // 1. 添加时间戳到参数（如果不存在）
        if (!isset($params['timestamp'])) {
            $params['timestamp'] = time();
        }

        // 2. 过滤空值和签名字段
        $params = array_filter($params, function ($value) {
            return $value !== null && $value !== ''; // 过滤掉空值或空字符串
        });

        if (isset($params['sign'])) {
            unset($params['sign']); // 移除签名字段
        }

        // 3. 按键名进行升序排序
        ksort($params);

        // 4. 拼接 key=value 形式并用 & 连接
        $queryString = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        // 5. 拼接密钥并生成哈希签名
        $stringToSign = $queryString . '&key=' . $this->secretKey;

        // 6. 根据需要选择哈希算法生成签名
        $signature = hash($this->hashAlgorithm, $stringToSign);

        if ($this->debug) {
            echo "调试信息：\n";
            echo "排序后的参数：" . json_encode($params) . "\n";
            echo "参与签名的字符串：" . $stringToSign . "\n";
            echo "生成的签名：" . $signature . "\n";
        }

        return $signature;
    }

    /**
     * 验证签名
     *
     * @param array $params 请求参数
     * @param string|null $providedSignature 客户端提供的签名
     * @return bool 签名是否有效
     */
    public function verifySignature(array $params, ?string $providedSignature): bool
    {
        if (!$providedSignature) {
            if ($this->debug) {
                echo "签名为空，无法验证。\n";
            }
            return false;
        }

        // 校验时间戳，防止重放攻击
        if (!isset($params['timestamp']) || abs(time() - (int)$params['timestamp']) > $this->signatureExpiry) {
            if ($this->debug) {
                echo "签名超时或缺失时间戳。\n";
            }
            return false;
        }

        // 通过同样的规则生成签名
        $calculatedSignature = $this->generateSignature($params);

        // 使用 hash_equals 比较签名，防止时序攻击
        $isValid = hash_equals($calculatedSignature, $providedSignature);

        if ($this->debug) {
            if ($isValid) {
                echo "签名验证成功！\n";
            } else {
                echo "签名验证失败！客户端签名：" . $providedSignature . "\n";
                echo "计算得出的签名：" . $calculatedSignature . "\n";
            }
        }

        return $isValid;
    }

    /**
     * 获取当前时间戳，可用于签名（统一时间标准）
     *
     * @return int
     */
    public function getCurrentTimestamp(): int
    {
        return time();
    }
}
