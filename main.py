import os
from hashlib import md5

from generator import linear_congruential_generator
from rc5 import generate_key, encrypt_file, decrypt_file, encrypt_string, decrypt_string

def generate_iv(length):
    # Генерація псевдовипадкових чисел
    random_numbers = linear_congruential_generator(2**31-1, 7**5, 17711, 31, length)
    # Конвертація чисел у байти
    return bytes((num % 256 for num in random_numbers))
def main():
    password = "123"  # Парольна фраза для шифрування/дешифрування
    input_file = "input.txt"  # Ім'я вхідного файлу
    blocksize = 64  # 64 біти
    rounds = 8  # 8 раундів

    # Генерація ключа з парольної фрази
    key = generate_key(password)

    # Генерація IV (ініціалізаційного вектора)

    iv = generate_iv(blocksize // 8)

    # Шифрування файлу
    output_file = f"{os.path.splitext(input_file)[0]}_encrypted.enc"
    decrypted_output_file = f"decrypted_{os.path.splitext(input_file)[0]}{os.path.splitext(input_file)[1]}"

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        encrypt_file(infile, outfile, key, blocksize, rounds, iv)

    print(f"Файл '{input_file}' зашифрований у '{output_file}'.")

    with open(output_file, 'rb') as infile, open(decrypted_output_file, 'wb') as outfile:
        decrypt_file(infile, outfile, key, blocksize, rounds)

    print(f"Файл '{output_file}' розшифрований у '{decrypted_output_file}'.")

    # Шифрування рядка
    input_string = "Hello, World!"  # Рядок для шифрування
    encrypted_string = encrypt_string(input_string.encode(), key, blocksize, rounds, iv)
    decrypted_string = decrypt_string(encrypted_string, key, blocksize, rounds)

    print(f"Зашифрований рядок: {encrypted_string.hex()}")  # Вивід зашифрованого рядка у шістнадцятковому форматі
    print(f"Розшифрований рядок: {decrypted_string.decode()}")  # Вивід розшифрованого рядка

if __name__ == "__main__":
    main()
