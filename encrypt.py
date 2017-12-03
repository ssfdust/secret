#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
from privy import hide, peek
from getpass import getpass

# 设置密码
def set_pass():
    password = getpass('Please enter your password:')
    confirm_pass = getpass('Please confirm your password:')
    if password != confirm_pass:
        return set_pass()
    else:
        return confirm_pass

# 询问密码
def ask_pass():
    password = getpass('Please enter your password:')

    return password

# 加密文件
def encrypt(plain, password):
    """
    :plain 明文数据bytes数据, File类型
    return 加密后的bytes数据
    """
    encryption = plain.name + '.pri'
    # secret 默认返回unicode类型转为bytes类型
    secret = hide(plain.read(), password, 6).encode('utf8')

    try:
        with open(encryption, 'w+b') as encrypted:
            encrypted.write(secret)
            print("Encrpt file {} success".format(plain.name))
    except Exception as e:
        print("Encrpt file {} failed".format(plain.name))
        raise(e)


def yes_no(answer):
    yes = set(['yes', 'y', 'ye'])
    no = set(['no', 'n', ''])

    while True:
        choice = input(answer).lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            print("Please repond with 'yes' or 'no'\n")

# 解密文件
def decrypt(secret, password):
    """
    :secret 密文数据bytes数据, File类型
    return 解密后的bytes数据
    """
    decryption = secret.name.split('.pri')[0]
    # 解析bytes为unicode
    try:
        plain = peek(secret.read().decode('utf8'), password)
    except ValueError:
        print("The password is wrong")
        sys.exit(0)

    try:
        with open(decryption, 'w+b') as decrypted:
            decrypted.write(plain)
            print("Decrypt file {} success".format(secret.name))
    except Exception as e:
        print("Decrypt file {} failed".format(secret.name))
        raise(e)

def main():
    parser = argparse.ArgumentParser(description="Encrypt your data with password")
    parser.add_argument('--encrypt', dest='en', action='store_true')
    parser.add_argument('--decrypt', dest='de', action='store_true')
    parser.add_argument('files', nargs="+")
    args = parser.parse_args()

    if args.en == True:
        password = set_pass()
        for filename in args.files:
            with open(filename, "rb") as f:
                encrypt(f, password)
            if yes_no("Would you delete the file {}(yes/no)? ".format(filename)):
                os.remove(filename)
    else:
        password = ask_pass()
        for filename in args.files:
            with open(filename, "rb") as f:
                decrypt(f, password)
            if yes_no("Would you delete the file {}(yes/no)? ".format(filename)):
                os.remove(filename)

    return 0

if __name__ == '__main__':
    main()
