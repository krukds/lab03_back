import struct

# Ініціалізація буферів (це стандартні початкові значення для MD5)
def initialize_md5_state():
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476
    return A, B, C, D

# Функції, які використовуються на різних етапах
def F(x, y, z):
    return (x & y) | (~x & z)

def G(x, y, z):
    return (x & z) | (y & ~z)

def H(x, y, z):
    return x ^ y ^ z

def I(x, y, z):
    return y ^ (x | ~z)

# Ліва ротація
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

# Константи для кожного раунду
K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

# Зсуви для кожного раунду
S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
]

def md5(data):
    # Перетворюємо дані в байти, якщо це рядок
    if isinstance(data, str):
        data = data.encode()

    # Довжина повідомлення у бітах
    original_bit_length = len(data) * 8

    # Додаємо 1 біт і нулі, щоб довжина була кратна 512
    data += b'\x80'
    data += b'\x00' * ((56 - len(data) % 64) % 64)

    # Додаємо довжину повідомлення (64 біти, маленький порядок байтів)
    data += struct.pack('<Q', original_bit_length)

    # Ініціалізація буферів
    A, B, C, D = initialize_md5_state()

    # Обробляємо повідомлення по 512-бітних блоках
    for chunk_offset in range(0, len(data), 64):
        chunk = data[chunk_offset:chunk_offset + 64]
        M = struct.unpack('<16I', chunk)  # Розбиваємо на 16 слів по 32 біти

        # Зберігаємо початкові значення регістрів
        a, b, c, d = A, B, C, D

        # Основний цикл MD5 (64 раунди)
        for i in range(64):
            if i < 16:
                f = F(b, c, d)
                g = i
            elif i < 32:
                f = G(b, c, d)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = H(b, c, d)
                g = (3 * i + 5) % 16
            else:
                f = I(b, c, d)
                g = (7 * i) % 16

            f = (f + a + K[i] + M[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + left_rotate(f, S[i])) & 0xFFFFFFFF

        # Додаємо результати до початкових значень регістрів
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # Повертаємо об'єднаний результат (128 біт)
    return struct.pack('<4I', A, B, C, D)


# def md5_hash(password):
#     # Переконайтеся, що password є рядком, і кодуйте його у байти
#     if isinstance(password, str):
#         return hashlib.md5(password.encode()).digest()  # Якщо рядок, кодуємо його
#     return hashlib.md5(password).digest()  # Якщо вже байти, просто хешуємо


