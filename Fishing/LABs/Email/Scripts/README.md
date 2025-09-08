# eml_attch_analyzer

Безопасный CLI-скрипт для анализа **.eml** писем:
Cчитывает хэши вложений выбранными алгоритмами и, если вложение — ZIP, потоково считает хэши **файлов внутри** архива **в памяти**, без записи на диск.
Поддерживает пароль для ZIP и имеет защиту от zip-бомб (лимиты чтения включены по умолчанию).

## Возможности
    - Хэширование вложений: `sha256` (по умолчанию), `md5`, `sha512`, `sha3_256`, и др. (`hashlib`).
    - ZIP-вложения: хэши внутренних файлов через `ZipFile.open()` (ничего не распаковывается на диск).
    - Пароль для ZIP: `-p/--zip-password` или `--ask-pass`.
    - Анти zip-бомба: лимиты чтения (пер-файл и суммарно).
    - Нулевые внешние зависимости (стандартная библиотека Python).

## Установка
```bash
    git clone https://github.com/<youruser>/eml_attch_analyzer.git
    cd eml_attch_analyzer
    python --version    # нужен Python 3.8+
    pip install -r requirements.txt   # пусто; стандартная библиотека
```

## Быстрый старт

    python eml_safe_hash_algo_pw.py examples/sample.eml

## Примеры

  SHA-256 (по умолчанию):

    python eml_safe_hash_algo_pw.py suspicious.eml

  SHA-256 + MD5:

    python eml_safe_hash_algo_pw.py suspicious.eml --algo sha256 --algo md5
   # или
    python eml_safe_hash_algo_pw.py suspicious.eml --algo sha256,md5

  С паролем:

    python eml_safe_hash_algo_pw.py suspicious.eml -p MySecret123
   # или без следа в истории
    python eml_safe_hash_algo_pw.py suspicious.eml --ask-pass

   Снять лимиты (только в песочнице):

    python eml_safe_hash_algo_pw.py suspicious.eml --zip-total-limit 0 --zip-member-limit 0

