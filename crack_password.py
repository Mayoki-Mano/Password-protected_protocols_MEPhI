import hashlib
import sys
import multiprocessing
from time import time


def hash_password(password, hash_func):
    """Функция для хеширования пароля с использованием заданной хеш-функции."""
    if hash_func == "MD4":
        try:
            from passlib.hash import nthash
            return nthash.hash(password)
        except ImportError:
            raise ImportError("MD4 requires the passlib library. Install it using 'pip install passlib'.")
    hash_func = getattr(hashlib, hash_func.lower())
    return hash_func(password.encode()).hexdigest()


def crack_hash(password, hash_func, hash_list):
    """Функция для проверки пароля против списка хешей."""
    password_hash = hash_password(password, hash_func)
    if password_hash in hash_list:
        return f"{password}:{password_hash}"
    return None


def read_hashes(file_path, encoding='utf-8'):
    """Функция для чтения хешей из файла."""
    with open(file_path, 'r', encoding=encoding) as f:
        return set(f.read().splitlines())


def read_wordlist(file_path, encoding='utf-8'):
    """Функция для чтения словаря из файла."""
    with open(file_path, 'r', encoding=encoding) as f:
        return f.read().splitlines()


def process_chunk(chunk, hash_func, hash_list, results):
    """Функция для обработки части хешей (в одном процессе)."""
    for password in chunk:
        result = crack_hash(password, hash_func, hash_list)
        if result:
            results.append(result)


def main():
    if len(sys.argv) != 5:
        print("Usage: python crack_password.py <wordlist> <encoding> <hash_function> <hashlist>")
        sys.exit(1)

    wordlist_file = sys.argv[1]
    encoding = sys.argv[2]
    hash_func = sys.argv[3].upper()
    hashlist_file = sys.argv[4]

    if hash_func not in ["MD4", "MD5", "SHA1", "SHA256", "SHA512"]:
        print(
            f"Error: Unsupported hash function '{hash_func}'. Supported functions are: MD4, MD5, SHA1, SHA256, SHA512.")
        sys.exit(1)
    if encoding not in ["UTF-8", "UTF-16-LE"]:
        print(f"Error: Unsupported encoding '{encoding}'. Supported encodings are: utf-8, utf-16-le.")
        sys.exit(1)

    # Чтение хешей из файла
    hash_list = read_hashes(hashlist_file, encoding)

    # Чтение словаря из файла
    wordlist = read_wordlist(wordlist_file, encoding)

    # Разделяем хеши на части для обработки в разных процессах
    num_processes = multiprocessing.cpu_count()  # Количество ядер
    chunk_size = len(wordlist) // num_processes
    if chunk_size == 0:
        chunk_size = 1
    chunks = [list(wordlist)[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]

    # Список для сохранения результатов
    manager = multiprocessing.Manager()
    results = manager.list()

    # Создаем процессы
    processes = []
    for chunk in chunks:
        process = multiprocessing.Process(target=process_chunk, args=(chunk, hash_func, hash_list, results))
        processes.append(process)
        process.start()
    start_time = time()
    # Ожидаем завершения всех процессов
    for process in processes:
        process.join()
    end_time = time()
    execution_time = end_time - start_time
    # Выводим результаты
    if results:
        for result in results:
            print(result)
    else:
        print("No matching hashes found.")
    print(f"Время выполнения программы: {execution_time:.4f} секунд")


if __name__ == "__main__":
    main()
