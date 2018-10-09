import hashlib
import os
from Crypto.Cipher import AES
# 编码格式
import base64
from binascii import b2a_hex, a2b_hex

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA


class Encrypts:
    """MD5 AES RSA 三种加密方法"""
    def __init__(self):
        # AES加密模式
        self.aes_mode = AES.MODE_ECB
        # AES秘钥，随机数值
        self.aes_key_size = 256
        # RSA秘钥对，随机数值
        self.rsa_count = 2048

    @staticmethod
    def md5_encrypt(plaintext):
        """ MD5加密
        :param plaintext: 需要加密的内容
        :return: encrypt_str密文
        """
        # 创建md5对象
        h1 = hashlib.md5()
        h1.update(plaintext.encode(encoding='utf-8'))   # 必须声明encode
        # 加密
        encrypt_str = h1.hexdigest()
        return encrypt_str

    def generate_aes_key(self):
        """AES秘钥生成"""
        # length for urandom
        key_size = self.aes_key_size
        u_len = int(key_size/8/4*3)
        # os.urandom()生成随机字符串
        aes_key = base64.b64encode(os.urandom(u_len))
        return aes_key

    def aes_encrypt(self, message, aes_key):
        """use AES to encrypt message,
        :param message: 需要加密的内容
        :param aes_key: 密钥
        :return: encrypted_message密文
        """
        # 加密模式
        mode = self.aes_mode
        if type(message) == str:
            message = bytes(message, 'utf-8')
        if type(aes_key) == str:
            aes_key = bytes(aes_key, 'utf-8')

        while len(aes_key) % 16 != 0:
            aes_key += b' '
        # message必须为16的倍数
        while len(message) % 16 != 0:
            message += b' '
        # 加密对象aes
        aes = AES.new(key=aes_key, mode=mode)
        encrypt_message = aes.encrypt(plaintext=message)
        return b2a_hex(encrypt_message)

    def generate_rsa_keys(self):
        """RSA秘钥对生成"""
        rsa_count = self.rsa_count
        # 随机数生成器
        random_generator = Random.new().read
        # rsa算法生成实例
        rsa = RSA.generate(rsa_count, random_generator)
        # master的秘钥对的生成
        rsa_public_key = rsa.publickey().exportKey()
        rsa_private_key = rsa.exportKey()
        return rsa_public_key, rsa_private_key

    @staticmethod
    def rsa_encrypt(message, rsa_public_key):
        """use RSA to encrypt message,
        :param message: 需要加密的内容
        :param rsa_public_key: 公钥(字节类型）
        :return: encrypt_msg_list密文列表
        """
        pub_key = RSA.importKey(rsa_public_key)
        # 加密对象
        cipher = Cipher_pkcs1_v1_5.new(pub_key)
        msg = message.encode('utf-8')
        # 分段加密
        default_encrypt_length = 245
        length = default_encrypt_length
        msg_list = [msg[i:i + length] for i in list(range(0, len(msg), length))]
        # 加密后信息列表
        encrypt_msg_list = []
        for msg_str in msg_list:
            cipher_text = base64.b64encode(cipher.encrypt(message=msg_str))
            encrypt_msg_list.append(cipher_text)
        return encrypt_msg_list


class Decrypts:
    """AES RSA 解密方法"""
    def __init__(self):
        # AES解密模式(须与加密模式一致）
        self.aes_mode = AES.MODE_ECB

    def aes_decrypt(self, encrypt_message, aes_key):
        """ AES解密
        :param encrypt_message: 密文
        :param aes_key: 秘钥
        :return: decrypt_text解密后内容
        """
        aes_mode = self.aes_mode
        aes = AES.new(key=aes_key, mode=aes_mode)
        decrypted_text = aes.decrypt(a2b_hex(encrypt_message))
        decrypted_text = decrypted_text.rstrip()  # 去空格
        return decrypted_text.decode()

    @staticmethod
    def rsa_decrypt(encrypt_msg_list, rsa_private_key):
        """ RSA解密
        :param encrypt_msg_list: 密文列表
        :param rsa_private_key: 私钥(字节类型)
        :return  解密后内容
        """
        random_generator = Random.new().read
        pri_key = RSA.importKey(rsa_private_key)
        cipher = Cipher_pkcs1_v1_5.new(pri_key)
        # 解密后信息列表
        msg_list = []
        for msg_str in encrypt_msg_list:
            msg_str = base64.decodebytes(msg_str)
            de_str = cipher.decrypt(msg_str, random_generator)
            msg_list.append(de_str.decode('utf-8'))
        return ''.join(msg_list)
