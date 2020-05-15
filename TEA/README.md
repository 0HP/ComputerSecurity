基于TEA源码，实现CBC与CTR模式的加密解密。
-------------------------------------------------------------

py程序，使用命令行运行：需要命令行参数4个
-key：秘钥文件、文件格式应为4行1列16进制数字符，不够4行的默认为0
-savefile：写入结果的文件
-module：选择加密/解密模式CBC或者CTR、输入其他则出错
-encrypt：加密算法，以及需要被加密的文件
-decrypt：解密算法，以及需要被解密的文件

-------------------------------------------------------------
可键入：TEA.py -h查看帮助说明
Please input in these format
TEA.py -k <KeyFile> -s <SaveFile> -m <CBC/CTR> -e <filename>
   or:TEA.py -k <KeyFile> -s <SaveFile> -m <CBC/CTR> -d <filename>
TEA.py --key=<KeyFile> --save=<SaveFile> --module=<CBC/CTR> --encrypt=<filename>
   or:TEA.py --key=<KeyFile> --save=<SaveFile> --module=<CBC/CTR> --decrypt=<filename>
-------------------------------------------------------------
输入示例：
TEA.py -k key.txt -s Crypt.txt -m CBC -e Plain.txt