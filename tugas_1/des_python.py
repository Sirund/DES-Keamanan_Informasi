import random


def permute(original, permutation_table):
    return [original[i - 1] for i in permutation_table]

def left_shift(key, shifts):
    return key[shifts:] + key[:shifts]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def string_to_bits(s):
    return [int(bit) for char in s for bit in format(ord(char), '08b')]

def bits_to_string(b):
    chars = [chr(int(''.join(map(str, b[i:i + 8])), 2)) for i in range(0, len(b), 8)]
    return ''.join(chars)

INITIAL_PERMUTATION = [58, 50, 42, 34, 26, 18, 10, 2,
                       60, 52, 44, 36, 28, 20, 12, 4,
                       62, 54, 46, 38, 30, 22, 14, 6,
                       64, 56, 48, 40, 32, 24, 16, 8,
                       57, 49, 41, 33, 25, 17, 9, 1,
                       59, 51, 43, 35, 27, 19, 11, 3,
                       61, 53, 45, 37, 29, 21, 13, 5,
                       63, 55, 47, 39, 31, 23, 15, 7]

INVERSE_PERMUTATION = [40, 8, 48, 16, 56, 24, 64, 32,
                       39, 7, 47, 15, 55, 23, 63, 31,
                       38, 6, 46, 14, 54, 22, 62, 30,
                       37, 5, 45, 13, 53, 21, 61, 29,
                       36, 4, 44, 12, 52, 20, 60, 28,
                       35, 3, 43, 11, 51, 19, 59, 27,
                       34, 2, 42, 10, 50, 18, 58, 26,
                       33, 1, 41, 9, 49, 17, 57, 25]

def generate_key():
    key = [random.randint(0, 1) for _ in range(64)]
    return key


def feistel_function(right_half, key):
    return xor(right_half, key[:32]) 

def des_encrypt(plain_text, key):
    plain_bits = string_to_bits(plain_text)
    plain_bits = permute(plain_bits, INITIAL_PERMUTATION) 

    left, right = plain_bits[:32], plain_bits[32:]

    for _ in range(16):
        temp = right[:]
        right = xor(left, feistel_function(right, key))
        left = temp

    combined = right + left 
    cipher_bits = permute(combined, INVERSE_PERMUTATION)

    return bits_to_string(cipher_bits)

def des_decrypt(cipher_text, key):
    cipher_bits = string_to_bits(cipher_text)
    cipher_bits = permute(cipher_bits, INITIAL_PERMUTATION)  

    left, right = cipher_bits[:32], cipher_bits[32:]

    for _ in range(16):
        temp = left[:]
        left = xor(right, feistel_function(left, key))
        right = temp

    combined = left + right
    plain_bits = permute(combined, INVERSE_PERMUTATION)

    return bits_to_string(plain_bits)

if __name__ == "__main__":
    key = generate_key()

    plain_text = "HELLO DES"

    encrypted_text = des_encrypt(plain_text, key)
    print(f"Encrypted Text: {encrypted_text}")

    decrypted_text = des_decrypt(encrypted_text, key)
    print(f"Decrypted Text: {decrypted_text}")
