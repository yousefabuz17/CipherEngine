import sys
import pytest
from pathlib import Path
from functools import partial

sys.path.append((Path(__file__).resolve().parents[1] / "src/cipher_engine").as_posix())
from cipher_engine import *


# XXX Utility objects and methods for testing.
main_tpath = Path(__file__).parent / "test_files"
cengine = CipherEngine()
whitespace = cengine._WHITESPACE
str_hash = cengine._calc_str_hash
validate_file_exists = lambda fp: Path(fp).is_file()
validate_ctuple = lambda ctuple, e=None: cengine._validate_ciphertuple(
    ctuple, external_params=e
)


def validate_encryption(fp):
    bytes_text = cengine._read_file(fp)
    encr_header = cengine._identifiers
    return bytes_text.startswith(encr_header)


@pytest.fixture(
    params=[
        (
            "plaintext",
            Path("test_ciphertexts_passkey.cfg"),
            main_tpath,
            1000,
        )
    ]
)
def test_text_params(request):
    return request.param


def test_cipher_texts(test_text_params):
    text, passkey_file, export_path, iterations = test_text_params
    original_hash = str_hash(text)
    encr_tuple = encrypt_text(
        text=text,
        file_name=passkey_file.stem,
        export_path=export_path,
        iterations=iterations,
    )
    assert validate_ctuple(encr_tuple)

    new_passkey = export_path / passkey_file
    assert validate_file_exists(new_passkey)

    decr_tuple = decrypt_text(passkey_file=new_passkey)
    assert decr_tuple.decrypted_text == encr_tuple.original_text
    assert decr_tuple.hash_value == encr_tuple.hash_value
    assert original_hash == decr_tuple.hash_value
    assert original_hash == encr_tuple.hash_value


@pytest.fixture(params=[(main_tpath / "test_unencrypted_file.txt", False, False, 1000)])
def test_files_params(request):
    return request.param


def test_cipher_files_wo_backup_or_overwrite(test_files_params):
    file, backup_file, overwrite_file, iterations = test_files_params
    encr_tuple = encrypt_file(
        file=file,
        backup_file=backup_file,
        overwrite_file=overwrite_file,
        iterations=iterations,
    )
    encrypted_file = Path(main_tpath / "encrypted_test_unencrypted_file.aes")
    decrypted_file = Path(main_tpath / "decrypted_encrypted_test_unencrypted_file.dec")
    passkey_file = Path(main_tpath / "encrypted_test_unencrypted_file_passkey.cfg")

    assert validate_ctuple(encr_tuple)
    assert (Path(__file__) / "backup").is_dir() is False
    assert all(map(validate_file_exists, (encrypted_file, passkey_file)))
    assert validate_encryption(encrypted_file)
    assert encr_tuple.decipher_keys == encr_tuple.decipher_keys

    decr_tuple = decrypt_file(passkey_file=passkey_file, overwrite_file=overwrite_file)
    assert decr_tuple.hash_value == encr_tuple.hash_value
    assert validate_file_exists(decrypted_file)


@pytest.fixture(params=[(CipherEngine._MAX_CAPACITY + 1, True, bytes)])
def test_max_capacity_param(request):
    return request.param


def test_cryptographic_params(test_max_capacity_param):
    too_large, true_val, b = test_max_capacity_param
    test_cases = [
        {"key_length": too_large},
        {"key_length": 0},
        bypass_test := {"key_length": 15},
        {"repeat": too_large},
        {"exclude": true_val, "include_all_chars": true_val},
    ]
    for case in test_cases:
        with pytest.raises(CipherException):
            generate_crypto_key(**case)

    assert generate_crypto_key(**bypass_test, bypass_keylength=true_val)

    bytes_key = generate_crypto_key(
        **bypass_test, bypass_keylength=true_val, urlsafe_encoding=true_val
    )
    assert type(bytes_key) is b


def test_cryptographic_exclude_chars():
    char_checker = cengine._char_checker
    excluder = cengine._exclude_type

    for t in excluder(return_dict=True):
        key = generate_crypto_key(exclude=t)
        assert cengine._compiler(excluder(t), key, escape_default=False) is None
        assert char_checker(t) is True

    all_chars = generate_crypto_key(include_all_chars=True)
    assert char_checker(all_chars)
    assert char_checker(whitespace) is False


@pytest.fixture(
    params=[
        (
            "plaintext",
            "password123",
            "AESpassword123",
            1000,
            3,
            32,
            8,
            1,
            True,
            ("beginning_header", "ending_header"),
            ".ini",
            {"aes_iv", "aes_passkey"},
            main_tpath,
        )
    ]
)
def test_config_params(request):
    return request.param


def test_config_parameters(test_config_params):
    (
        text,
        passkey,
        aes_pass,
        iterations,
        num_salts,
        salt_bytes_size,
        r,
        p,
        bypass_klen,
        identifiers,
        serializer,
        aes_params,
        e_path,
    ) = test_config_params
    encryptor = partial(
        encrypt_text,
        text=text,
        passkey=passkey,
        iterations=iterations,
        num_of_salts=num_salts,
        salt_bytes_size=salt_bytes_size,
        bypass_keylength=bypass_klen,
        p=p,
        export_path=e_path,
        serializer=serializer.lstrip("."),
    )

    with pytest.raises(CipherException):
        encryptor(r=0)
        encryptor(identifiers=("", whitespace))

    basic_encrypt = encryptor(
        file_name=(basic_file := "test_basic_encrypt_params"),
        r=r,
        identifiers=identifiers,
    )
    aes_encrypt = encryptor(
        file_name=(aes_file := "test_aes_encrypt_params"),
        aes_passkey=aes_pass,
        advanced_encryption=True,
        r=r,
        identifiers=identifiers,
    )
    assert validate_file_exists((e_path / basic_file).with_suffix(serializer))
    assert validate_file_exists((e_path / aes_file).with_suffix(serializer))
    assert aes_params.issubset(basic_encrypt._asdict()) is False
    assert aes_params.issubset(aes_encrypt._asdict()) is True

    def parse_config(cfg, encrypted_type=None):
        str2any = cengine._str2any
        parse_func = partial(cengine._parse_config, main_tpath / cfg)
        str_hex = (
            lambda s, hashed=True: str_hash(s).encode().hex()
            if hashed
            else s.encode().hex()
        )
        assert parse_func(section_key="r_and_p") == str((r, p))
        assert parse_func(section_key="salt_bytes_size") == str(salt_bytes_size)
        assert parse_func(section_key="iterations") == str(
            2 ** cengine._log2_conversion(iterations)
        )
        assert parse_func(section_key="id1") == identifiers[0]
        assert parse_func(section_key="id2") == identifiers[1]

        decipher_keys = str2any(parse_func(section_key="decipher_keys"))
        salt_values = str2any(parse_func(section_key="salt_values"))
        assert len(decipher_keys) == num_salts
        assert len(salt_values) == num_salts

        passkey_param = str2any(parse_func(section_key="passkey"))
        assert passkey_param[0][: len(passkey)] == passkey and passkey_param[
            1
        ] == str_hex(passkey, hashed=False)

        assert parse_func(section="CIPHER_INFO", section_key="original_text") == text
        encrypted_text = parse_func(section="CIPHER_INFO", section_key="encrypted_text")
        assert (
            cengine._check_headers(encrypted_text, headers=identifiers, positive=True)
            is True
        )
        if encrypted_type == "aes":
            aes_passkey_param = str2any(parse_func(section_key="aes_passkey"))
            assert (
                aes_passkey_param[0] == aes_pass
                and aes_passkey_param[1]
                == str_hex(aes_pass)[: len(aes_passkey_param[1])]
            )

    parse_config("test_basic_encrypt_params.ini")
    parse_config("test_aes_encrypt_params.ini", encrypted_type="aes")


@pytest.fixture(params=[({"unknown_attr": ""}, {}, True)])
def test_manual_kwgs_params(request):
    return request.param


def test_engine_parameters(test_manual_kwgs_params):
    kwg_param, empty_kwg, T = test_manual_kwgs_params
    with pytest.raises((CipherException, TypeError)):
        CipherEngine(**kwg_param)
        encrypt_text(**kwg_param)
        encrypt_file(**kwg_param)
        quick_encrypt(**kwg_param)
        DecipherEngine(**kwg_param)
        decrypt_text(**kwg_param)
        decrypt_file(**kwg_param)
        quick_decrypt(**kwg_param)
        decrypt_text(manual_kwgs=kwg_param)
        decrypt_file(manual_kwgs=kwg_param)
        quick_decrypt(manual_kwgs=kwg_param)
        DecipherEngine(ciphertuple=T, passkey_file=T, manual_kwgs=T)
        DecipherEngine(ciphertuple=None, passkey_file=None, manual_kwgs=empty_kwg)


@pytest.fixture(
    params=[
        (main_tpath / "test_engine_namedtuples.txt", "plaintext123", 1000, False, True)
    ]
)
def test_namedtuples_names(request):
    return request.param


def test_engine_namedtuples(test_namedtuples_names):
    def name_matches(nt, m):
        assert nt.__module__ == m

    file, text, iterations, F, overwrite = test_namedtuples_names
    default_attrs = {"iterations": iterations, "export_passkey": F, "backup_file": F}
    ct, qct, dt, qdt = (
        "CipherTuple",
        "QCipherTuple",
        "DecipherTuple",
        "QDecipherTuple",
    )
    encr_text = encrypt_text(text=text, **default_attrs)
    qencr_text = quick_encrypt(text=text, **default_attrs)
    name_matches(encr_text, ct)
    name_matches(qencr_text, qct)

    decr_text = decrypt_text(ciphertuple=encr_text)
    qdecr_text = quick_decrypt(ciphertuple=qencr_text)
    name_matches(decr_text, dt)
    name_matches(qdecr_text, qdt)

    encr_file = encrypt_file(file=file, **default_attrs)
    decr_file = decrypt_file(ciphertuple=encr_file, overwrite_file=overwrite)
    name_matches(encr_file, ct)
    name_matches(decr_file, dt)

    qencr_file = quick_encrypt(file=file, **default_attrs)
    decr_file = quick_decrypt(ciphertuple=qencr_file, overwrite_file=overwrite)
    name_matches(qencr_file, qct)
    name_matches(decr_file, qdt)


@pytest.fixture(
    params=[
        (
            "testing quick engines.",
            main_tpath / "test_quick_engines.txt",
            "quick_password",
            False,
            True,
        )
    ]
)
def test_quick_engines_params(request):
    return request.param


def test_quick_engines(test_quick_engines_params):
    text, file, passk, F, T = test_quick_engines_params
    default_params = {
        "passkey": passk,
        "export_passkey": T,
        "backup_file": F,
        "overwrite_file": T,
        "bypass_keylength": T,
    }

    def verify_ctuple(ctuple, type_file=False, type_decrypt=False):
        encr_params = {
            "original_file" if type_file else "original_text",
            "encrypted_file" if type_file else "encrypted_text",
            "hash_value",
            "passkey",
        }
        decr_params = {
            "decrypted_file" if type_file else "decrypted_text",
            "hash_value",
        }
        if type_decrypt:
            assert validate_ctuple(ctuple, e=decr_params)
            if type_file:
                assert ctuple.decrypted_file == file
                assert ctuple.hash_value == cengine._calc_file_hash(file)
            else:
                assert ctuple.decrypted_text == text
                assert ctuple.hash_value == str_hash(text)
        else:
            assert validate_ctuple(ctuple, e=encr_params)
            if type_file:
                assert ctuple.original_file == file
                assert ctuple.encrypted_file == file
                assert ctuple.hash_value == cengine._calc_file_hash(file)
            else:
                assert ctuple.original_text == text
                assert ctuple.hash_value == str_hash(text)
            assert ctuple.passkey[0] == passk

    qtext_encr = quick_encrypt(
        text=text, file_name=main_tpath / "test_quick_encrypt_text", **default_params
    )
    qtext_decr = quick_decrypt(ciphertuple=qtext_encr, overwrite_file=T)
    verify_ctuple(qtext_encr)
    verify_ctuple(qtext_decr, type_decrypt=True)

    qfile_encr = quick_encrypt(
        file=file, file_name=main_tpath / "test_quick_encrypt_file", **default_params
    )
    qfile_decr = quick_decrypt(ciphertuple=qfile_encr, overwrite_file=T)
    verify_fctuple = partial(verify_ctuple, type_file=True)
    verify_fctuple(qfile_encr)
    verify_fctuple(qfile_decr, type_decrypt=True)


def test_gui_passkey(monkeypatch, capsys):
    passk = "testing"
    qctuple = quick_encrypt(
        text="hello", export_passkey=False, gui_passphrase=True, bypass_keylength=True
    )
    monkeypatch.setattr("tkinter.simpledialog.askstring", lambda *args, **kwargs: passk)
    assert qctuple.passkey[0] == passk


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
