import sys
import pytest
from pathlib import Path
from functools import partial
from string import digits, punctuation, ascii_letters, whitespace

sys.path.append((Path(__file__).resolve().parents[1] / "src/cipher_engine").as_posix())
from cipher_engine import *

main_tpath = Path(__file__).parent / "test_files"
crypto_key = generate_crypto_key()
cengine = CipherEngine()

validate_file_exists = lambda __file: __file.is_file()
validate_ctuple = lambda __ctuple: CipherEngine._validate_ciphertuple(__ctuple)


def validate_encryption(__file):
    bytes_text = cengine._bytes_read(__file)
    encr_header = cengine._identifiers
    return bytes_text.startswith(encr_header)


@pytest.fixture(
    params=[
        (
            "plaintext",
            Path("test_ciphertexts_passkey.ini"),
            main_tpath,
            Path("test_ciphertexts_passkey"),
        )
    ]
)
def test_text_params(request):
    return request.param


def test_cipher_texts(test_text_params):
    text, passkey_file, export_path, file_name = test_text_params
    encr_tuple = encrypt_text(text=text, file_name=file_name, export_path=export_path)
    assert validate_ctuple(encr_tuple)

    new_passkey = export_path / passkey_file
    assert validate_file_exists(new_passkey)

    decr_tuple = decrypt_text(passkey_file=new_passkey)
    assert decr_tuple.decrypted_text == encr_tuple.original_text
    assert decr_tuple.hash_value == encr_tuple.hash_value


@pytest.fixture(params=[(main_tpath / "test_unencrypted_file.txt", False, False)])
def test_files_params(request):
    return request.param


def test_cipher_files_wo_backup_or_overwrite(test_files_params):
    file, backup_file, overwrite_file = test_files_params
    encr_tuple = encrypt_file(
        file=file, backup_file=backup_file, overwrite_file=overwrite_file
    )
    encrypted_file = Path(main_tpath / "encrypted_test_unencrypted_file.aes")
    decrypted_file = Path(main_tpath / "decrypted_encrypted_test_unencrypted_file.dec")
    passkey_file = Path(main_tpath / "encrypted_test_unencrypted_file_passkey.ini")

    assert validate_ctuple(encr_tuple)
    assert not (Path(__file__) / "backup").is_dir()
    assert all(list(map(validate_file_exists, (encrypted_file, passkey_file))))
    assert validate_encryption(encrypted_file)
    assert encr_tuple.decipher_keys == encr_tuple.decipher_keys

    decr_tuple = decrypt_file(passkey_file=passkey_file, overwrite_file=False)
    assert decr_tuple.hash_value == encr_tuple.hash_value
    assert validate_file_exists(decrypted_file)


@pytest.fixture(params=[(int(1e8))])
def test_max_capacity_param(request):
    return request.param


def test_cryptographic_params(test_max_capacity_param):
    int8 = test_max_capacity_param
    test_cases = [
        {"key_length": int8},
        {"key_length": 0},
        {"repeat": int8},
        {"exclude": True, "include_all_chars": True},
    ]
    for case in test_cases:
        with pytest.raises(CipherException):
            generate_crypto_key(**case)


def test_cryptographic_exclude_chars():
    not_compiler = lambda *args: not cengine._compiler(*args, escape_default=False)

    digits_ = generate_crypto_key(exclude="digits")
    assert not_compiler(digits, digits_)

    punct = generate_crypto_key(exclude="punct")
    assert not_compiler(punctuation, punct)

    ascii_ = generate_crypto_key(exclude="ascii")
    assert not_compiler(ascii_letters, ascii_)

    digits_punct = generate_crypto_key(exclude="digits_punct")
    assert not_compiler((digits + punctuation), digits_punct)

    ascii_punct = generate_crypto_key(exclude="ascii_punct")
    assert not_compiler((ascii_letters + punctuation), ascii_punct)

    digits_ascii = generate_crypto_key(exclude="digits_ascii")
    assert not_compiler((digits + ascii_letters), digits_ascii)

    all_chars = generate_crypto_key(include_all_chars=True)
    assert not_compiler((digits + ascii_letters + punctuation), all_chars)
    assert not_compiler(whitespace, all_chars)


# @pytest.fixture(params=[(
#                     main_tpath / 'test_unencrypted_file_w_bkp.txt',
#                     64,
#                     True,
#                     True,
#                     True
#                 )])
# def test_files_params(request):
#     return request.param

# def test_cipher_files_w_backup_and_overwrite(test_files_params):
#     file, key_length, min_power, backup_file, overwrite_file = test_files_params
#     encr_tuple = encrypt_file(file=file,
#                             key_length=key_length,
#                             min_power=min_power,
#                             backup_file=backup_file,
#                             overwrite_file=overwrite_file)
#     encrypted_file = decrypted_file = Path(file).with_suffix('.aes')
#     decrypted_file = Path(main_tpath / 'decrypted_encrypted_test_unencrypted_file.dec')
#     passkey_file = Path(file.stem) / '_passkey.ini'

#     assert CipherEngine._validate_ciphertuple(encr_tuple)
#     assert (Path(__file__) / 'backup').is_dir()
#     assert validate_file_exists(encrypted_file)
#     assert validate_encryption(encrypted_file)
#     assert encr_tuple.decipher_key == encr_tuple.decipher_key

#     decr_tuple = decrypt_file(passkey_file=passkey_file,
#                                 overwrite_file=False)
#     assert decr_tuple.hash_value == encr_tuple.hash_value
#     assert validate_file_exists(decrypted_file)
