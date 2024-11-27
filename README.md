一个利用RSA和AES进行混合加密的PHP库
安装命令:composer require faj1/rsa

使用例子请参考测试文件,对文本进行AES加密,再对AES密码进行RAS加密,返回加密后的文本和加密后的AES密码和IV,解密利用RAS解密AES的密码,再利用密码解密获取明文


