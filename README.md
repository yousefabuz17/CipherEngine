# CipherEngine

`CipherEngine` is a Python library that provides tools for encrypting and decrypting files and text data using symmetric key cryptography. It uses secure algorithms and includes features such as key derivation, salt generation, and file integrity checks.

# Table of Contents

- [Primary Features](#primary-features)
- [Enhanced Security Measures](#enhanced-security-measures)
- [CipherEngine Class](#cipherengine-class)
    - [Attributes](#attributes)
    - [Methods](#methods)
    - [Example](#example)
- [DecipherEngine Class](#decipherengine-class)
    - [Overview](#overview)
    - [Attributes](#attributes-1)
    - [Methods](#methods-1)
    - [Example](#example-1)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Generate a Secure Cryptographic Key](#generate-a-secure-cryptographic-key)
- [Quickly Encrypt/Decrypt Text With Ease](#quickly-encryptdecrypt-text-with-ease)
- [Encrypt Text using CipherEngine.encrypt_text](#encrypt-text-using-cipherengineencrypt_text)
- [Encrypt a file using CipherEngine.encrypt_file](#encrypt-a-file-using-cipherengineencrypt_file)
- [Requirements](#requirements)
- [Risk Disclaimer](#risk-disclaimer)
- [Conclusion](#conclusion)


## Primary Features

- **File Encryption and Decryption**: Securely encrypt and decrypt files using symmetric key cryptography, incorporating advanced security measures such as PBKDF2 key derivation and unique encryption identifiers.

- **Text Encryption and Decryption**: Effortlessly encrypt and decrypt text data, ensuring confidentiality with robust cryptographic techniques.

    > **Quick-CipherText** - Rapidly encrypts and decrypts text data while providing essential information for seamless on-the-go operations.

- **Passphrase Generation**: Generate highly secure passphrases with customizable options to strengthen the foundation of your cryptographic keys.

- **Key Derivation**: Implement advanced key derivation functions, including PBKDF2, to enhance the security of your cryptographic keys and protect against brute-force attacks.

- **Backup and Restore**: Opt for optional creation of backups for original files before encryption, offering a safety net for data preservation. Efficiently restore files to their original state during the decryption process.

- **Export Passphrase**: Export passphrases to separate files for convenient and secure storage, ensuring that sensitive information is handled with the utmost care.

## Enhanced Security Measures

The CipherEngine incorporates the following advanced security measures:

- **PBKDF2 (Password-Based Key Derivation Function 2)**: Strengthen cryptographic keys by making key derivation computationally intensive, thwarting potential brute-force attacks.

- **Unique Encryption Identifiers**: Introduce a unique identifier during encryption to enhance security and protect against potential vulnerabilities.

- **Initialization Vectors (IV) and Salts**: Enhance security further by incorporating Initialization Vectors (IV) and salts. IVs add unpredictability to the encryption process, preventing patterns in ciphertexts, while salts contribute to unique key derivation, preventing rainbow table attacks.

>*The CipherEngine is designed to offer a comprehensive and secure solution for cryptographic operations, leveraging industry-standard techniques to safeguard your sensitive data.*

## CipherEngine Class

### Attributes

- `passkey`: The passphrase or key used for encryption (optional).
- `key_length`: The length of the cryptographic decipher key (default: 32).
- `iterations`: The number of iterations for key derivation.
- `exclude_chars`: Characters to exclude during passphrase generation (default: punctuation).
    > ***Exclude chars options: Specify one of the following options to exclude from key generation for efficient reference.***
    - `digits`: Includes digits (0-9).
    - `punct`: Includes punctuation characters.
    - `ascii`: Includes ASCII letters (both uppercase and lowercase).
    - `digits_punct`: Includes both digits and punctuation characters.
    - `ascii_punct`: Includes both ASCII letters and punctuation characters.
    - `digits_ascii`: Includes both digits and ASCII letters.
    
- `backup_file`: Flag indicating whether to create a backup of the original file (default: True).
- `export_passkey`: Flag indicating whether to export the passphrase to a separate file (default: True).
- `include_all_chars`: Flag indicating whether to include all characters during passphrase generation (default: False).
- `min_power`: Flag indicating whether to use the minimum power for key derivation (default: False).
- `max_power`: Flag indicating whether to use the maximum power for key derivation (default: False).
- `hash_type`: The hash type used in encryption.
- `algorithm_type`: The type of algorithm used in encryption.
- `serializer`: The type of serialization for exporting the passkey file ('json' or 'ini').
- `gui_passphrase`: Flag indicating whether to use a GUI for passphrase input (default: False).
- `bypass_keylength`: Flag indicating whether to bypass the minimum key length requirement (default: False).

### Methods

- `encrypt_file()`: Encrypts a specified file.
- `encrypt_text()`: Encrypts a specified text.
- `quick_encrypt()`: Quickly encrypts text data and exports necessary information on-the-go.
    > **Back-bone for quick_ciphertext**

### Example
```python
cipher = CipherEngine(passkey='my_secret_key', iterations=1000)
cipher.encrypt_file()
```
---
## DecipherEngine Class

### Overview

The `DecipherEngine` class, an extension of the CipherEngine, is dedicated to decrypting data encrypted through the CipherEngine. It seamlessly operates with configuration files generated by the CipherEngine during the encryption process.

### Attributes

- `ciphertuple` (NamedTuple): A NamedTuple containing details generated during the quick encryption process. It includes information such as the algorithm type, passkey, encrypted text, hash type, hash value, CPU power, original text, and salt value.
- `text` (Any | None): The encrypted text to be decrypted. This parameter represents the ciphertext obtained from the encryption process.
- `decipher_key` (Any | None): The decryption passphrase or key required to decrypt the encrypted text. It is crucial for the successful decryption of the provided ciphertext.
- `hash_value` (Any | None): The hash value of the original data. This value is used for integrity checking during the decryption process. It ensures that the decrypted text matches the original data, providing data integrity verification.
- `passkey_file`: str | Path: The path to the file containing the encryption details.
- `overwrite_file`: bool | None: Flag indicating whether to overwrite the original file during decryption (default: False).
- `verbose`: bool | None: Flag indicating whether to print verbose messages (default: False).


### Methods

- `decrypt_file()`: Decrypts an encrypted file.
- `decrypt_text()`: Decrypts encrypted text.
- `quick_decrypt()`: Quickly decrypts text data and exports necessary information on-the-go.
    > **Back-bone for quick_deciphertext**

### Example

```python
decipher = DecipherEngine(passkey_file='encrypted_file_passkey.ini')
decipher.decrypt_file()
```

### Returns
> - **Each method returns a NamedTuple instance, providing a convenient way to handle and pass around the encryption results.**
> - **This NamedTuple can be seamlessly utilized with the decryption methods, eliminating the need for manually specifying each attribute during the decryption process.**

---

# Installation

To use `CipherEngine` in your Python project, you can install it via pip. Open your terminal or command prompt and run the following command:

```bash
pip install cipher-engine
```
---

# Usage Examples

## Import Module
```python
from cipherengine import *
# __all__ = (
# 'CipherEngine', 'DecipherEngine',
# 'encrypt_file', 'decrypt_file',
# 'encrypt_text', 'decrypt_text',
# 'quick_ciphertext', 'quick_deciphertext',
# 'CipherException', 'generate_crypto_key',
# )
```

## Generate a Secure Cryptographic Key
```python
# Generate a cryptographic key using specified parameters
crypto_key = generate_crypto_key(key_length=int(1e5))
# Output: Mc2nTJ2zosmNxEu6cXF99lapaEEgWxjt....

crypto_key = generate_crypto_key(include_all_chars=True)
# Output: YGWm;2]-vLT*YS;My/mm5e\B[db$xfI

crypto_key = generate_crypto_key(exclude='digits_punct')
# Output: wmsjRLFxnVmXJfHGzjVNgWtRogZZQeGs
```

## Quickly Encrypt/Decrypt Text With Ease
```python
# Quick encryption of text data using CipherEngine.quick_encrypt
result_quick_ciphertext = quick_ciphertext(text='Hello, World!', export_passkey=False)
# Output: (NamedTuple)
# CipherTuple(algorithm_type='AES', decipher_key='546d746a556d746965555a464e6b4a5256553568563035584e466c4D62553172635735536355316e4D456f3d', encrypted_text='-----BEGIN CIPHERENGINE CRYPTOGRAPHIC ENCRYPTED KEY-----gAAAAABlnW67n3zkDLzoLzpTtpOVdrzKwXI5qNsqXOV8bFL34sYekvRwxAH4WciesqC3UPUBB8H7Gklm5GQdV12ZzElZrCEtEg==', hash_type='SHA512', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f', iterations=139239, iv_value=None, original_text='Hello, World!', salt_value=None)

# Quick decryption of text data
result_quick_deciphertext = quick_deciphertext(
    text=result_quick_ciphertext.encrypted_text,
    decipher_key='my_secret_key',
    hash_value='...'
)
# Output: (NamedTuple)
# DecipherTuple(decrypted_text='Hello, World!', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f')

# Preferably can pass in the NamedTuple instead.
quick_deciphertext(ciphertuple=result_quick_ciphertext)
```

## Encrypt Text using CipherEngine.encrypt_text
```python
# Encrypt text using CipherEngine.encrypt_text
result_encrypt_text = encrypt_text(text='Hello, World!', key_length=32, export_path='output')
# Output: (NamedTuple)
# CipherTuple(algorithm_type='AES', decipher_key='4p8keHiYD5snme5DVUU8UuxKY2A9aFTc', encrypted_text='QKZrhffcL1TWS2J2fg==', hash_type='SHA512', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f', iterations=139239, iv_value='bbaf9031f11a2a7ac1a8e6384d73a874', original_text='Hello, World!', salt_value='ad12ab5e72028b16a77e03a0d4f7fce0')

# Decrypt text using DecipherEngine.decrypt_text
result_decrypt_text = decrypt_text(
    ciphertuple=result_encrypt_text,
    passkey_file='output/info.ini',
    export_path='output/decrypted')
# Output: (NamedTuple)
# DecipherTuple(decrypted_text='Hello, World!', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f')
# or NamedTuple
decrypt_text(ciphertuple=result_encrypt_text)
```

## Encrypt a File using CipherEngine.encrypt_file
```python
# Encrypt a file using CipherEngine.encrypt_file
result_encrypt_file = encrypt_file(
    file='test.txt',
    passkey=crypto_key,
    iterations=int(1e6),
    export_path='output')
# Output: (NamedTuple)
# CipherTuple(algorithm_type='AES', decipher_key='J]TTE~:vGzQ]E*?i;0br&!0,tY+zxSN^', encrypted_file='test.aes', hash_type='SHA512', hash_value='01e675506785122a5055d79a9e8fcb919c1b7838bd1d1209cd42ac67730d1f90', iterations=69619, iv_value='b26516ae7a074299bed53bbb92ebc34f', original_file='test.aes', salt_value='8cd661ff966f42fc8174623ff51e8bdd')

# Decrypt a file using DecipherEngine.decrypt_file
result_decrypt_file = decrypt_file(
    passkey_file='output/test_passkey.ini')
# Output: (NamedTuple)
# DecipherTuple(decrypted_file=PosixPath('test.aes'), hash_value='5c0c10f62a2798b8f4f2cbb3d677fc9330d87250d3a1b27830ab050ba21c87ab')
```

# Requirements
- **Python**: 3.10 or above
  - *Note: This project specifically requires Python 3.10. Compatibility issues have been identified when using Python 3.9 due to the usage of the kw_only parameter for dataclasses, which is crucial for this project.*

- **cryptography**: ~=41.0.4
- **numpy**: ~=1.26.3
- **psutil**: ~=5.9.7
- **pytest**: ~=7.4.3
- **setuptools**: ~=68.2.2

## Risk Disclaimer

Ensuring the proper and secure handling of data is of paramount importance when employing the `CipherEngine` library. To minimize the risk of potential data loss, consider the following guidelines:

- **Backup File Parameter**: Always make use of the `backup_file` parameter to generate backups of your original files before initiating the encryption process. This provides an added layer of safety, allowing you to restore data in case of unexpected issues.

- **Imperfect Encryption**: It's essential to recognize that, despite robust encryption measures, no encryption method can be deemed entirely infallible. Under specific circumstances, encrypted data may still be susceptible to decryption. Be cognizant of the inherent limitations and complexities involved in cryptographic processes.

- **USE AT YOUR OWN RISK**: The author of the `CipherEngine` library holds no responsibility for any data loss that may occur during the usage of the library. Users are advised to exercise caution, adhere to best practices, and implement proper backup procedures to mitigate potential risks.

Exercise responsibility and vigilance in your usage of the library, keeping these considerations in mind. Understand that while the `CipherEngine` offers powerful encryption and decryption capabilities, it is not exempt from potential risks associated with the broader landscape of data security.

## Conclusion

In summary, the `CipherEngine` project presents a versatile and robust framework for symmetric key cryptography. Discover the available classes and methods to seamlessly incorporate secure encryption and decryption functionality into your Python projects.