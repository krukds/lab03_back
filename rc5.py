import os

from md5 import md5


def generate_key(password):
    # Хешуємо парольну фразу (MD5)
    first_hash = md5(password)  # Перший хеш (128 біт)

    # Хешуємо перший хеш (MD5)
    second_hash = md5(first_hash)  # Другий хеш (128 біт)

    # Об'єднуємо перший і другий хеш для отримання 256-бітного ключа
    key = second_hash + first_hash  # K = H(H(P)) || H(P)
    return key[:32]  # Повертаємо перші 32 байти (256 біт)


def _rotate_left(val, r_bits, max_bits):
    r_bits = r_bits % max_bits
    return ((val << r_bits) | (val >> (max_bits - r_bits))) & (2 ** max_bits - 1)

def _rotate_right(val, r_bits, max_bits):
    r_bits = r_bits % max_bits
    return ((val >> r_bits) | (val << (max_bits - r_bits))) & (2 ** max_bits - 1)

def _expand_key(key, wordsize, rounds):
    def _align_key(key, align_val):
        while len(key) % align_val:
            key += b'\x00'
        L = []
        for i in range(0, len(key), align_val):
            L.append(int.from_bytes(key[i:i + align_val], byteorder='little'))
        return L

    def _const(w):
        if w == 16:
            return (0xB7E1, 0x9E37)
        elif w == 32:
            return (0xB7E15163, 0x9E3779B9)
        elif w == 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    def _extend_key(w, r):
        P, Q = _const(w)
        S = [P] + [0] * (2 * (r + 1) - 1)
        for i in range(1, len(S)):
            S[i] = (S[i - 1] + Q) % (2 ** w)
        return S

    aligned = _align_key(key, wordsize // 8)
    S = _extend_key(wordsize, rounds)

    # Key mixing
    m = len(aligned)
    t = len(S)
    A = B = i = j = 0

    for k in range(3 * max(m, t)):
        A = S[i] = _rotate_left(S[i] + A + B, 3, wordsize)
        B = aligned[j] = _rotate_left(aligned[j] + A + B, (A + B) % (2 ** wordsize), wordsize)

        i = (i + 1) % t
        j = (j + 1) % m

    return S

def _encrypt_block(data, expanded_key, blocksize, rounds, iv):
    w = blocksize // 2
    b = blocksize // 8

    A = int.from_bytes(data[:b // 2], byteorder='little') ^ int.from_bytes(iv, byteorder='little')
    B = int.from_bytes(data[b // 2:], byteorder='little') ^ int.from_bytes(iv, byteorder='little')

    A = (A + expanded_key[0]) % (2 ** w)
    B = (B + expanded_key[1]) % (2 ** w)

    for i in range(1, rounds + 1):
        A = (_rotate_left((A ^ B), B, w) + expanded_key[2 * i]) % (2 ** w)
        B = (_rotate_left((A ^ B), A, w) + expanded_key[2 * i + 1]) % (2 ** w)

    return A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')

def _decrypt_block(data, expanded_key, blocksize, rounds, iv):
    w = blocksize // 2
    b = blocksize // 8

    A = int.from_bytes(data[:b // 2], byteorder='little')
    B = int.from_bytes(data[b // 2:], byteorder='little')

    for i in range(rounds, 0, -1):
        B = _rotate_right((B - expanded_key[2 * i + 1]) % (2 ** w), A, w) ^ A
        A = _rotate_right((A - expanded_key[2 * i]) % (2 ** w), B, w) ^ B

    B = (B - expanded_key[1]) % (2 ** w)
    A = (A - expanded_key[0]) % (2 ** w)

    A ^= int.from_bytes(iv, byteorder='little')
    B ^= int.from_bytes(iv, byteorder='little')

    # Переконайтеся, що значення A та B в межах допустимого діапазону
    A = A % (2 ** w)
    B = B % (2 ** w)

    return A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')


def pad(data, blocksize):
    padding_length = blocksize - (len(data) % blocksize)
    return data + bytes([0] * padding_length)

def unpad(data):
    return data.rstrip(b'\x00')

def encrypt_file(infile, outfile, key, blocksize, rounds, iv, file_extension):
    expanded_key = _expand_key(key, blocksize, rounds)

    # Записуємо IV
    outfile.write(iv)

    # Записуємо розмір розширення файлу (1 байт) і саме розширення
    outfile.write(len(file_extension).to_bytes(1, byteorder='little'))
    outfile.write(file_extension.encode())

    # Записуємо розмір оригінального файлу
    infile.seek(0, os.SEEK_END)
    original_size = infile.tell()
    infile.seek(0)
    outfile.write(original_size.to_bytes(8, byteorder='little'))  # 8 байтів для збереження розміру файлу

    chunk = infile.read(blocksize // 8)
    while chunk:
        chunk = pad(chunk, blocksize // 8)
        encrypted_chunk = _encrypt_block(chunk, expanded_key, blocksize, rounds, iv)
        outfile.write(encrypted_chunk)
        chunk = infile.read(blocksize // 8)

def decrypt_file(infile, outfile, key, blocksize, rounds):
    expanded_key = _expand_key(key, blocksize, rounds)

    # Читаємо IV
    iv = infile.read(blocksize // 8)

    # Читаємо розмір розширення і саме розширення файлу
    extension_length = int.from_bytes(infile.read(1), byteorder='little')
    file_extension = infile.read(extension_length).decode()

    # Читаємо оригінальний розмір файлу
    original_size = int.from_bytes(infile.read(8), byteorder='little')

    chunk = infile.read(blocksize // 8)
    decrypted_data = bytearray()

    while chunk:
        decrypted_chunk = _decrypt_block(chunk, expanded_key, blocksize, rounds, iv)
        decrypted_data.extend(decrypted_chunk)
        chunk = infile.read(blocksize // 8)

    # Обрізаємо зайві байти до оригінального розміру файлу
    decrypted_data = decrypted_data[:original_size]
    outfile.write(decrypted_data)

    return file_extension
def encrypt_string(data, key, blocksize, rounds, iv):
    expanded_key = _expand_key(key, blocksize, rounds)
    padded_data = pad(data, blocksize // 8)

    encrypted_data = bytearray()

    for i in range(0, len(padded_data), blocksize // 8):
        chunk = padded_data[i:i + blocksize // 8]
        encrypted_chunk = _encrypt_block(chunk, expanded_key, blocksize, rounds, iv)
        encrypted_data.extend(encrypted_chunk)

    return iv + encrypted_data  # Повертаємо IV разом із зашифрованими даними

def decrypt_string(encrypted_data, key, blocksize, rounds):
    iv = encrypted_data[:blocksize // 8]  # Отримуємо IV
    expanded_key = _expand_key(key, blocksize, rounds)
    decrypted_data = bytearray()

    for i in range(blocksize // 8, len(encrypted_data), blocksize // 8):
        chunk = encrypted_data[i:i + blocksize // 8]
        decrypted_chunk = _decrypt_block(chunk, expanded_key, blocksize, rounds, iv)
        decrypted_data.extend(decrypted_chunk)

    return unpad(decrypted_data)  # Повертаємо розшифровані дані без паддінгу
