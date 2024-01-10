import sys
import pytest
from pathlib import Path

sys.path.extend([(Path(__file__).resolve().parents[1] / 'src/cipher_engine/').as_posix()])
from cipher_engine import *

main_tpath = Path(__file__).parent / 'test_files'
crypto_key = generate_crypto_key()

def validate_file_exists(__file):
    return __file.is_file()

def validate_encryption(__file):
    with open(__file, mode='rb') as file:
        bytes_text = file.read()
    encr_header = '-----BEGIN CIPHERENGINE CRYPTOGRAPHIC ENCRYPTED KEY-----'.encode()
    return bytes_text.startswith(encr_header)


@pytest.fixture(params=[(
                    'plaintext', # Text to be encrypted/decrypted
                    crypto_key, # Custom passkey used for encryption/decryption
                    Path('test_ciphertexts_passkey.ini'), # Custom file name for exporting encryption details
                    main_tpath, # Custom path for testing
                    Path('test_ciphertexts_passkey'), # File name for exporting decryption details
                    int(1e5) # Number of iterations
                )])
def test_text_params(request):
    return request.param


def test_cipher_texts(test_text_params):
    """
    Test the encryption and decryption of texts using different cipher functions.
    
    Parameters:
        test_text_params (Tuple): A tuple containing the parameters for the test, including
            - text (str): The plaintext to be encrypted.
            - passkey (str): The passkey used for encryption.
            - passkey_file (str): The filename for storing the passkey.
            - export_path (Path): The directory path for exporting the encrypted content.
            - file_name (str): The filename for storing the encrypted content.
            - iterations (int): The number of iterations to be cycled through the encryption process.
    
    Raises:
        AssertionError: If any of the encryption or decryption steps fail.
    
    Test Steps:
        1. Encrypt the provided text using the `encrypt_text` function.
        2. Verify that all attributes in the resulting encrypted tuple are non-empty.
        3. Verify the file's encryption info existence.
        4. Decrypt the encrypted text using the `decrypt_text` function and compare it with the original text.
        --------------------------------------------------------------------------------------------------------
        5. Perform a quick encryption using the `quick_ciphertext` function.
        6. Verify that all attributes in the resulting quick encrypted tuple are non-empty.
        7. Decrypt the quick encrypted text using the `quick_deciphertext` function and compare it with the original text.
    """
    
    #XXX Encrypt/Decrypt Texts
    text, passkey, passkey_file, export_path, file_name, iterations = test_text_params
    encr_tuple = encrypt_text(text=text,
                            passkey=passkey,
                            file_name=file_name,
                            iterations=iterations,
                            export_path=export_path)
    
    assert CipherEngine._validate_ciphertuple(encr_tuple)
    
    # Ensure that the provided iterations value matches the one on file.
    assert encr_tuple.iterations == iterations
    
    new_passkey = export_path / passkey_file
    # Verify the existence of the passkey file
    assert validate_file_exists(new_passkey)
    
    decr_tuple = decrypt_text(passkey_file=new_passkey)
    # Ensure that the decrypted text matches the original text along with its hash value
    assert decr_tuple.decrypted_text == encr_tuple.original_text
    assert decr_tuple.hash_value == encr_tuple.hash_value

@pytest.fixture(params=[(
                    'plaintext',
                    main_tpath,
                    Path('test_ciphertexts_passkey')
                )])
def test_quick_text_params(request):
    return request.param

def test_quick_cipher_texts(test_quick_text_params):
    text, export_path, file_name = test_quick_text_params
    
    #XXX Quick Encrypt/Decrypt Texts (Same procedure)
    quick_encr_tuple = quick_ciphertext(text=text,
                                        file_name=file_name.with_name('test_quick_ciphertexts_passkey'),
                                        export_path=export_path)
    assert CipherEngine._validate_ciphertuple(quick_encr_tuple)
    quick_decrypting = quick_deciphertext(ciphertuple=quick_encr_tuple)
    assert quick_decrypting.decrypted_text == quick_encr_tuple.original_text
    assert quick_decrypting.hash_value == quick_encr_tuple.hash_value

@pytest.fixture(params=[(
                    main_tpath / 'test_unencrypted_file.txt',
                    64,
                    True,
                    False,
                    False
                )])
def test_files_params(request):
    return request.param

def test_cipher_files_wo_backup_or_overwrite(test_files_params):
    file, key_length, min_power, backup_file, overwrite_file = test_files_params
    encr_tuple = encrypt_file(file=file,
                            key_length=key_length,
                            min_power=min_power,
                            backup_file=backup_file,
                            overwrite_file=overwrite_file)
    encrypted_file = Path(main_tpath / 'encrypted_test_unencrypted_file.aes')
    decrypted_file = Path(main_tpath / 'decrypted_encrypted_test_unencrypted_file.dec')
    passkey_file = Path(main_tpath / 'encrypted_test_unencrypted_file_passkey.ini')
    
    assert CipherEngine._validate_ciphertuple(encr_tuple)
    assert not (Path(__file__) / 'backup').is_dir()
    assert all(list(map(validate_file_exists, (encrypted_file, passkey_file))))
    assert validate_encryption(encrypted_file)
    assert encr_tuple.decipher_key == encr_tuple.decipher_key
    
    decr_tuple = decrypt_file(passkey_file=passkey_file,
                                overwrite_file=False)
    assert decr_tuple.hash_value == encr_tuple.hash_value
    assert validate_file_exists(decrypted_file)

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

@pytest.fixture(params=[(
                    'plaintext',
                    'password123'
                )])
def test_invalid_passkey(request):
    return request.param

def test_invalid_passkey_w_text(test_invalid_passkey):
    text, passkey = test_invalid_passkey
    encr_tuple = encrypt_text(text=text,
                            passkey=passkey,
                            export_passkey=False)
    
    assert CipherEngine._validate_ciphertuple(encr_tuple)
    assert encr_tuple.decipher_key != passkey