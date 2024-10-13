import os
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import FileResponse
from hashlib import md5

from starlette.middleware.cors import CORSMiddleware

from generator import linear_congruential_generator
from rc5 import generate_key, encrypt_file, decrypt_file, encrypt_string, decrypt_string

app = FastAPI()

# Дозволити CORS для певного домену
origins = [
    "http://localhost:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Налаштуйте відповідно до ваших потреб
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],  # Додайте цей заголовок
)

def generate_iv(length):
    # Генерація псевдовипадкових чисел
    random_numbers = linear_congruential_generator(2 ** 31 - 1, 7 ** 5, 17711, 31, length)
    # Конвертація чисел у байти
    return bytes((num % 256 for num in random_numbers))


@app.post("/encrypt-file/")
async def encrypt_file_endpoint(file: UploadFile = File(...), password: str = Form(...)):
    blocksize = 64
    rounds = 8
    key = generate_key(password)
    iv = generate_iv(blocksize // 8)

    input_file = file.filename
    file_extension = os.path.splitext(input_file)[1]  # Оригінальне розширення файлу
    encrypted_file_name = f"{os.path.splitext(input_file)[0]}_encrypted.enc"

    with open(input_file, 'wb') as f:
        f.write(await file.read())

    with open(input_file, 'rb') as infile, open(encrypted_file_name, 'wb') as outfile:
        encrypt_file(infile, outfile, key, blocksize, rounds, iv, file_extension)

    return FileResponse(
            encrypted_file_name,
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename={encrypted_file_name}"}
    )

@app.post("/decrypt-file/")
async def decrypt_file_endpoint(file: UploadFile = File(...), password: str = Form(...)):
    blocksize = 64
    rounds = 8
    key = generate_key(password)

    input_file = file.filename
    decrypted_file_name = f"decrypted_{os.path.splitext(input_file)[0]}"  # Ім'я файлу без розширення

    with open(input_file, 'wb') as f:
        f.write(await file.read())

    with open(input_file, 'rb') as infile, open(decrypted_file_name, 'wb') as outfile:
        file_extension = decrypt_file(infile, outfile, key, blocksize, rounds)

    # Додаємо відновлене розширення файлу
    final_decrypted_file = f"{decrypted_file_name}{file_extension}"
    os.rename(decrypted_file_name, final_decrypted_file)  # Перейменовуємо файл з відновленим розширенням

    return FileResponse(
            final_decrypted_file,
            media_type='application/octet-stream',
            headers={"Content-Disposition": f"attachment; filename={final_decrypted_file}"}
    )

@app.post("/encrypt-string/")
async def encrypt_string_endpoint(data: str = Form(...), password: str = Form(...)):
    blocksize = 64
    rounds = 8
    key = generate_key(password)
    iv = generate_iv(blocksize // 8)

    encrypted_string = encrypt_string(data.encode(), key, blocksize, rounds, iv)
    return {"encrypted_string": encrypted_string.hex()}


@app.post("/decrypt-string/")
async def decrypt_string_endpoint(data: str = Form(...), password: str = Form(...)):
    blocksize = 64
    rounds = 8
    key = generate_key(password)

    encrypted_bytes = bytes.fromhex(data)
    decrypted_string = decrypt_string(encrypted_bytes, key, blocksize, rounds)

    return {"decrypted_string": decrypted_string.decode()}


# Запуск сервера
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)