import sys
from time import time
from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes


INPUT_PATH, OUTPUT_PATH = sys.argv[1], sys.argv[2]

BLOCK_SIZE = 64

KEY1 = b"good_key"
KEY2 = b"nice_key"
KEY3 = b"some_key"

DES_1 = DES.new(KEY1, DES.MODE_ECB)
DES_2 = DES.new(KEY2, DES.MODE_ECB)
DES_3 = DES.new(KEY3, DES.MODE_ECB)

while True:
    try:
        reference_key = DES3.adjust_key_parity(get_random_bytes(24))
        break
    except ValueError:
        pass


def timer(func):
    def wrap_func(*args, **kwargs):
        t1 = time()
        result = func(*args, **kwargs)
        t2 = time()
        print(f'\n[{func.__name__}] Execution time: {(t2-t1):.4f}s')
        return result
    return wrap_func


@timer
def encrypt(input_path, output_path, chunksize=64*1024):
    with open(input_path, 'rb') as source:
        with open(output_path, 'wb') as output:
            while True:
                chunk = source.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 8 != 0:
                    chunk += b' ' * (8 - len(chunk) % 8)

                encrypted_line = DES_1.encrypt(chunk)
                double_encrypted_line = DES_2.decrypt(encrypted_line)
                triple_encrypted_line = DES_3.encrypt(double_encrypted_line)

                output.write(triple_encrypted_line)

@timer
def reference_encryption(input_path, chunksize=64*1024):
    cipher = DES3.new(reference_key, DES3.MODE_ECB)
    with open(input_path, 'rb') as source:
        with open('reference_encryption.txt', 'wb') as output:
            while True:
                chunk = source.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 8 != 0:
                    chunk += b' ' * (8 - len(chunk) % 8)

                output.write(cipher.encrypt(chunk))


@timer
def decryption(input_path, output_path, chunksize=64*1024):
    with open(input_path, 'rb') as source:
        with open(output_path, 'wb') as output:
            while True:
                chunk = source.read(chunksize)
                if len(chunk) == 0:
                    break

                first_decryption = DES_3.decrypt(chunk)
                second_decryption = DES_2.encrypt(first_decryption)
                third_decryption = DES_1.decrypt(second_decryption)

                output.write(third_decryption)


if __name__ == '__main__':
    encrypt(INPUT_PATH, OUTPUT_PATH)
    reference_encryption(INPUT_PATH)
    decryption(OUTPUT_PATH, 'decrypted.txt')

