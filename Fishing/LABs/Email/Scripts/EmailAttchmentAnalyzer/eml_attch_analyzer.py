#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, argparse, email, hashlib, io, zipfile, getpass
from email import policy
from pathlib import Path

# Безопасные значения по умолчанию (включены всегда)
DEFAULT_ZIP_TOTAL_READ_LIMIT  = 200 * 1024 * 1024  # 200 MB суммарно по архиву
DEFAULT_ZIP_MEMBER_READ_LIMIT =  50 * 1024 * 1024  # 50 MB на один файл
CHUNK_SIZE = 4096

def parse_algos(algo_args):
    """Поддержка нескольких алгоритмов: --algo sha256 --algo md5 или --algo sha256,md5"""
    algos = []
    for a in algo_args or ["sha256"]:
        algos.extend([x.strip().lower() for x in a.split(",") if x.strip()])
    if not algos:
        algos = ["sha256"]
    # проверим поддержку
    for a in algos:
        try:
            hashlib.new(a)
        except ValueError:
            print(f"❌ Unsupported algorithm: {a}")
            sys.exit(2)
    return algos

def make_hashers(algos):
    """Создать набор хэшеров одновременно: имя -> объект"""
    return {a: hashlib.new(a) for a in algos}

def update_hashers_from_stream(hashers, readable, max_bytes=None):
    """Потоково обновлять сразу несколько хэшеров.
       Возвращает (hexdigests|None, total_read). Если превышен лимит — hexdigests=None."""
    total = 0
    while True:
        chunk = readable.read(CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            return None, total
        for h in hashers.values():
            h.update(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}, total

def hash_bytes_multi(b, algos):
    hashers = make_hashers(algos)
    bio = io.BytesIO(b)
    while True:
        ch = bio.read(CHUNK_SIZE)
        if not ch:
            break
        for h in hashers.values():
            h.update(ch)
    return {a: h.hexdigest() for a, h in hashers.items()}

def analyze_eml(path, algos, zip_total_limit, zip_member_limit, zip_password_bytes):
    eml_bytes = Path(path).read_bytes()
    msg = email.message_from_bytes(eml_bytes, policy=policy.default)

    any_attachments = False
    warn_member_limit = False
    warn_total_limit  = False

    for part in msg.iter_attachments():
        any_attachments = True
        name = part.get_filename() or "attachment.bin"
        data = part.get_payload(decode=True)

        print(f"\n{name}")
        if data is None:
            print("  ERROR: no decodable payload")
            continue

        att_hashes = hash_bytes_multi(data, algos)
        print("  Signature(hex):", data[:8].hex())
        for a, hv in att_hashes.items():
            print(f"  {a.upper()}: {hv}")

        # Если это ZIP — считаем хэши внутренних файлов (в памяти)
        if data.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    if zip_password_bytes:
                        z.setpassword(zip_password_bytes)
                    print("  ZIP contents:")
                    total_read = 0
                    for info in z.infolist():
                        enc = bool(info.flag_bits & 0x1)
                        meta = f"    - {info.filename}  size={info.file_size}  encrypted={enc}"

                        # Если каталог/директория
                        if info.is_dir():
                            print(f"{meta}  [directory]")
                            continue

                        # Проверка суммарного лимита до открытия потока
                        if zip_total_limit is not None and total_read >= zip_total_limit:
                            print(f"{meta}  HASH=SKIPPED (zip total-read limit reached)")
                            warn_total_limit = True
                            continue

                        # Открываем поток файла внутри ZIP
                        try:
                            with z.open(info, "r") as f:
                                # лимит по конкретному файлу + остаток по архиву
                                allow = zip_member_limit
                                if zip_total_limit is not None:
                                    remain = max(0, zip_total_limit - total_read)
                                    allow = min(allow, remain) if allow is not None else remain

                                # Считаем сразу несколько алгоритмов
                                file_hashes, read_bytes = update_hashers_from_stream(
                                    make_hashers(algos), f, max_bytes=allow
                                )
                                total_read += read_bytes

                                if file_hashes is None:
                                    print(f"{meta}  HASH=PARTIAL (read limit exceeded)")
                                    warn_member_limit = True
                                else:
                                    # аккуратный вывод всех хэшей
                                    hstr = "  ".join(f"{a.upper()}={hv}" for a, hv in file_hashes.items())
                                    print(f"{meta}  {hstr}")

                        except RuntimeError as e:
                            # неверный пароль / шифрование заголовков и т.п.
                            print(f"{meta}  HASH=N/A ({e})")
                        except zipfile.BadZipFile as e:
                            print(f"{meta}  HASH=N/A (corrupted zip: {e})")
            except zipfile.BadZipFile as e:
                print(f"  ZIP ERROR: {e} (corrupted or truncated)")
            except RuntimeError as e:
                print(f"  ZIP RUNTIME ERROR: {e}")

    if not any_attachments:
        print("No attachments found in this EML.")

    # Итоговые предупреждения
    if warn_member_limit or warn_total_limit:
        print("\n=== WARNING SUMMARY ===")
        if warn_member_limit:
            print(f"* Some files exceeded per-file read limit "
                  f"({zip_member_limit if zip_member_limit is not None else 'unlimited'} bytes) "
                  "→ possible zip-bomb or extremely large compressed member.")
        if warn_total_limit:
            print(f"* ZIP total-read limit reached "
                  f"({zip_total_limit if zip_total_limit is not None else 'unlimited'} bytes) "
                  "→ archive may expand very large (zip-bomb heuristic).")

def main():
    ap = argparse.ArgumentParser(
        description="Safe EML analyzer: hashes attachments and inner ZIP files in-memory; supports multiple algos and ZIP password."
    )
    ap.add_argument("eml_file", help="Path to .eml file")
    ap.add_argument("--algo", action="append",
                    help="Hash algorithm(s). Repeat or comma-separate. Default: sha256. "
                         "Examples: --algo sha256 --algo md5  OR  --algo sha256,md5,sha512")
    ap.add_argument("-p", "--zip-password", help="Password for encrypted ZIPs (used for all ZIP attachments)")
    ap.add_argument("--ask-pass", action="store_true", help="Prompt for ZIP password interactively")
    ap.add_argument("--zip-total-limit", type=int, default=DEFAULT_ZIP_TOTAL_READ_LIMIT,
                    help="Max total bytes from ZIP members (default: 200MB, 0=unlimited)")
    ap.add_argument("--zip-member-limit", type=int, default=DEFAULT_ZIP_MEMBER_READ_LIMIT,
                    help="Max bytes per ZIP member (default: 50MB, 0=unlimited)")
    args = ap.parse_args()

    if args.ask_pass and args.zip_password:
        print("Choose either --ask-pass or --zip-password, not both.")
        sys.exit(2)

    algos = parse_algos(args.algo)

    pwd = None
    if args.zip_password:
        pwd = args.zip_password.encode("utf-8")
    elif args.ask_pass:
        pwd = getpass.getpass("ZIP password: ").encode("utf-8")

    total_limit  = None if args.zip_total_limit == 0 else args.zip_total_limit
    member_limit = None if args.zip_member_limit == 0 else args.zip_member_limit

    analyze_eml(args.eml_file, algos, total_limit, member_limit, pwd)

if __name__ == "__main__":
    sys.exit(main() or 0)
