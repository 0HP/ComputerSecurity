RSA加解密及签名认证
------------------------------
针对简单的文本文件进行加解密；针对任意格式文件签名或者认证；

文件Get_e_n.py生成公私钥对(私钥1024bits,公钥2048bits)
文件RSA.py实现加解密及签名认证功能

------------------------------
加密时密文写入文件名为"EncryptText.txt"的文件中
解密时明文写入文件名为"DecryptText.txt"的文件中
签名时将签名后的哈希码放入文件名为"Signatrue.txt"的文件中