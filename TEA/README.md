����TEAԴ�룬ʵ��CBC��CTRģʽ�ļ��ܽ��ܡ�
-------------------------------------------------------------

py����ʹ�����������У���Ҫ�����в���4��
-key����Կ�ļ����ļ���ʽӦΪ4��1��16�������ַ�������4�е�Ĭ��Ϊ0
-savefile��д�������ļ�
-module��ѡ�����/����ģʽCBC����CTR���������������
-encrypt�������㷨���Լ���Ҫ�����ܵ��ļ�
-decrypt�������㷨���Լ���Ҫ�����ܵ��ļ�

-------------------------------------------------------------
�ɼ��룺TEA.py -h�鿴����˵��
Please input in these format
TEA.py -k <KeyFile> -s <SaveFile> -m <CBC/CTR> -e <filename>
   or:TEA.py -k <KeyFile> -s <SaveFile> -m <CBC/CTR> -d <filename>
TEA.py --key=<KeyFile> --save=<SaveFile> --module=<CBC/CTR> --encrypt=<filename>
   or:TEA.py --key=<KeyFile> --save=<SaveFile> --module=<CBC/CTR> --decrypt=<filename>
-------------------------------------------------------------
����ʾ����
TEA.py -k key.txt -s Crypt.txt -m CBC -e Plain.txt