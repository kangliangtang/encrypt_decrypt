import time
from encrypt_decrypts_new import Encrypts, Decrypts


# -------------------测试-----------------------------------
def encryption():
    en_obj = Encrypts()
    # -------------------MD5-------------------------
    crypt_text = en_obj.md5_encrypt(plaintext='md5 test')
    print('md5密文：', crypt_text)
    print('---'*20)

    # -------------------AES--------------------------
    msg = 'this is AES test'*200
    aes_key = en_obj.generate_aes_key()
    aes_encrypt_text = en_obj.aes_encrypt(message=msg, aes_key=aes_key)
    print('AES密文：', aes_encrypt_text)
    print('AES秘钥：', aes_key)
    print('AES秘钥类型：', type(aes_key))
    # print('AES加密模式：', mode)
    print('---' * 20)

    # -------------------RSA-------------------------------
    # 存储秘钥对
    rsa_pub, rsa_pri = en_obj.generate_rsa_keys()

    # with open('./RSASecretkey/public.pem', 'wb+') as f:
    #     f.write(rsa_pub)
    # with open('./RSASecretkey/private.pem', 'wb+') as f:
    #     f.write(rsa_pri)

    # 读取RSA秘钥对文件获取
    # with open('./RSASecretkey/public.pem') as f:
    #     rsa_pub = f.read()
    #     # f.write(rsa_pub)
    # with open('./RSASecretkey/private.pem') as f:
    #     rsa_pri = f.read()

    # rsa加密
    msg = 'this is RSA test'*100
    rsa_encrypt_msg = en_obj.rsa_encrypt(message=msg, rsa_public_key=rsa_pub)
    print('RSA密文：', rsa_encrypt_msg)
    print('RSA公钥类型：', type(rsa_pub))
    print('RSA私钥类型：', type(rsa_pri))
    print('---' * 20)

    return aes_encrypt_text, aes_key, rsa_encrypt_msg, rsa_pri


def decryption():
    aes_encrypt_text, aes_key, rsa_encrypt_msg, rsa_prikey = encryption()

    de_obj = Decrypts()
    # AES解密
    de_text = de_obj.aes_decrypt(encrypt_message=aes_encrypt_text, aes_key=aes_key)
    print('aes解密后:', de_text)
    # RAS解密
    de_rsa_text = de_obj.rsa_decrypt(encrypt_msg_list=rsa_encrypt_msg, rsa_private_key=rsa_prikey)
    print('rsa解密后：', de_rsa_text)


if __name__ == '__main__':
    s = time.time()
    for i in range(20):
        print('********第%d测试**********' % (i+1))
        # 生成RSA keys测试
        obj = Encrypts()
        pub, pri = obj.generate_rsa_keys()
        print('pub---', pub)
        print('pri---', pri)

    # 加解密测试
    # decryption()

    e = time.time()
    print('--测试时间---', (e-s))
