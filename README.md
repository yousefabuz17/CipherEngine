<img src="logo/cipher-engine-logo.jpg" alt="CipherEngine Logo" width="200"/> 

# CipherEngine 
[![PyPI version](https://badge.fury.io/py/cipher-engine.svg)](https://badge.fury.io/py/cipher-engine)
[![Downloads](https://pepy.tech/badge/cipher-engine)](https://pepy.tech/project/cipher-engine)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](https://opensource.org/license/apache-2-0/)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://github.com/yousefabuz17/CipherEngine/blob/main/README.md)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-blue.svg)](https://www.python.org/dev/peps/pep-0008/)
---
Welcome to `CipherEngine`, a powerful Python library dedicated to symmetric key cryptography. This documentation offers a detailed exploration of the library, highlighting key features, enhanced security measures, and practical usage examples. Please refer to the table of contents below to navigate through the documentation.

---

# Table of Contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Primary Features](#primary-features)
    - [Data Encryption and Decryption](#data-encryption-and-decryption)
    - [Text Encryption and Decryption](#text-encryption-and-decryption)
    - [Passphrase Generation and Key Derivation](#passphrase-generation-and-key-derivation)
    - [Backup Management](#backup-management)
    - [Export Passkey Configuration File](#export-passkey-configuration-file)
    - [Data Integrity Assurance Mechanism](#data-integrity-assurance-mechanism)
- [Enhanced Security Measures](#enhanced-security-measures)
    - [PBKDF2](#pbkdf2)
    - [Unique Encryption Identifiers](#unique-encryption-identifiers)
    - [Salt and IV Generation](#salt-and-iv-generation)
    - [Cipher Feedback](#cipher-feedback)
- [Key Generation](#key-generation)
    - [Overview](#overview)
    - [Code Base](#code-base)
    - [All Available Characters](#all-available-characters)
    - [Character Set Exclusion Options](#character-set-exclusion-options)
        - [Exclusion Chart](#exclusion-chart)
        - [Exclusion Examples](#exclusion-examples)
- [CipherEngine Class](#cipherengine-class)
    - [Overview](#overview)
    - [Attributes](#attributes)
    - [Methods](#methods)
    - [Example](#example)
- [DecipherEngine Class](#decipherengine-class)
    - [Overview](#overview)
    - [Attributes](#attributes-1)
    - [Methods](#methods-1)
    - [Example](#example-1)
- [Class Engine Return State](#class-engine-return-state)
    - [CipherTuple](#ciphertuple)
- [Usage Examples](#usage-examples)
    - [Generate a Secure Cryptographic Key](#generate-a-secure-cryptographic-key)
    - [Quickly Encrypt/Decrypt Text With Ease](#quickly-encryptdecrypt-text-with-ease)
    - [Encrypt Text using CipherEngine.encrypt_text](#encrypt-text-using-cipherengineencrypt_text)
    - [Decrypt Text using DecipherEngine.decrypt_text](#decrypt-text-using-decrypt_text)
    - [Encrypt a File using CipherEngine.encrypt_file](#encrypt-a-file-using-encrypt_file)
    - [Decrypt a File using DecipherEngine.decrypt_file](#decrypt-a-file-using-decrypt_file)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
- [Roadmap](#roadmap)
    - [Upcoming Features](#upcoming-features)
    - [Progress Table](#progress-table)
- [Contributors and Feedback](#contributors-and-feedback)
    - [Contributing](#contributing)
    - [Feedback](#feedback)
- [Important Notes](#important-notes)
    - [Maximum Iterations and Key Length](#maximum-iterations-and-key-length)
    - [Beta Release Status](#beta-release-status)
    - [Critical Considerations for Optimal Usage](#critical-considerations-for-optimal-usage)
- [Risk Disclaimer](#risk-disclaimer)
- [Change-log](./CHANGELOG.md)
- [Conclusion](#conclusion)
---

# Requirements
- #### **`Python`**: ~=3.10
- #### **`cryptography`**: ~=41.0.4
- #### **`numpy`**: ~=1.26.3
- #### **`psutil`**: ~=5.9.7
- #### **`pytest`**: ~=7.4.3
- #### **`setuptools`**: ~=68.2.2
> *This project mandates the use of `Python 3.10` or later versions. Compatibility issues have been identified with `Python 3.9` due to the utilization of the `kw_only` parameter in dataclasses, a critical component for the project. It is important to note that the project may undergo a more stringent backward compatibility structure in the near future.*
---

# Installation

To use `CipherEngine` in your Python project, you can install it via pip. Open your terminal or command prompt and run the following command:

```bash
pip install cipher-engine
pip install -r requirements.txt
```
---

# Primary Features
### Data Encryption and Decryption
- Securely encrypt and decrypt data (files/strings) using symmetric key cryptography, incorporating advanced security measures.
---

### Text Encryption and Decryption
- Effortlessly encrypt and decrypt text data, ensuring confidentiality with robust cryptographic techniques.

    > **`<class-engine>.quick_(en/de)crypt`** - Rapidly encrypts and decrypts text data while providing essential information for seamless on-the-go operations.
---

### Passphrase Generation and Key Derivation
- Generate highly secure passphrases with customizable options to strengthen the foundation of your cryptographic keys.
- Utilizes advanced key derivation functions, including PBKDF2, to enhance the security of your cryptographic keys and protect against brute-force attacks.
    > *Refer to [Key Generation](#key-generation) for additional details.*
---

### Backup Management
- Opt for optional creation of backups for original files before encryption, offering a safety net for data preservation.
- Efficiently restore files to their original state during the decryption process if `overwrite_file` parameter is set to True.
---

### Export Passkey Configuration File
- Facilitates the exportation of the passkey configuration file into a distinct file, ensuring that sensitive information is handled with the utmost care.
---

### Data Integrity Assurance Mechanism

- **Cryptographic Hash Generation**: Upon the initial processing of a file or text string, the CipherEngine generates a unique cryptographic hash value for that specific data. This hash serves as a tamper-evident representation of the content, as any alterations to the data will result in a distinct hash value.
```python
    @classmethod
    def _calc_file_hash(cls, __file: P) -> str:
        file = cls._validate_file(__file)
        sha256_hash = hashlib.sha256()
        with open(__file, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @classmethod
    def _calc_str_hash(cls, __text: str):
        valid_text = cls._validate_object(__text, type_is=str).encode()
        hash_ = hashlib.sha256()
        hash_.update(valid_text)
        return hash_.hexdigest()
```

- **Cryptographic Hash Comparison**: The current hash value of the data is compared to the stored hash value in the passkey configuration file. Any disparities between these values indicate potential unauthorized changes to the data.
>*Additionally checks if the encrypted data starts and ends with the designated encryption identifier. This step ensures the correct application of encryption and further validates the data's integrity.*
---

# Enhanced Security Measures
## Overview
The `CipherEngine` library incorporates a wide range of security measures to ensure the confidentiality and integrity of your data. These measures include:
### PBKDF2
- ***`PBKDF2 (Password-Based Key Derivation Function 2)`** is a key derivation function that employs a pseudorandom function to derive cryptographic keys from a password. It is a widely used key derivation function, offering robust security and protection against brute-force attacks.*
- Strengthen cryptographic keys by making key derivation computationally intensive, thwarting potential brute-force attacks.

### Unique Encryption Identifiers
- Introduce a unique `encryption_header` during encryption to enhance security and protect against potential vulnerabilities.
- This unique identifier that is generated during the encryption process and is appended to the beginning of the encrypted file. It is used to verify the integrity of the encrypted file during the decryption process, ensuring that the file has not been tampered with.
- The default `encryption_header` is as follows:
    - *-----BEGIN CIPHERENGINE CRYPTOGRAPHIC ENCRYPTED KEY-----*
    - *-----END CIPHERENGINE CRYPTOGRAPHIC ENCRYPTED KEY-----*

### Salt and IV Generation
- Strengthen security measures by integrating Initialization Vectors (IV) and salts. IVs introduce unpredictability into the encryption process, thwarting patterns in ciphertexts, while salts aid in unique key derivation, mitigating the risk of rainbow table attacks.
    > Utilizes with `secrets.token_bytes` method to generate cryptographically secure random numbers.
    ```python
    @staticmethod
    def _gen_random(__size: int=16) -> bytes:
        return secrets.token_bytes(__size)
    ```

### Cipher Feedback
- Utilizes the `Cipher` Feedback (`CFB8`) mode from the Cipher algorithm, incorporating an additional layer of security into the encryption process.
- The mode leverages `default_backend()` for `Cipher`, ensuring robust cryptographic operations within the CipherEngine. This choice enhances the unpredictability of ciphertexts, reinforcing the overall security of the encryption mechanism.

>*The `CipherEngine` is designed to offer a comprehensive and on-the-go secure method for cryptographic operations, leveraging industry-standard techniques to safeguard your sensitive data.*
---

# Key Generation
## Overview
`generate_crypto_key` is a comprehensive method that provides a robust and flexible key generation mechanism, allowing you to create keys tailored to your specific security needs.

When generating cryptographic keys using the `generate_crypto_key` method, you have the flexibility to customize the key based on specific character sets. (Refer to [Character Set Exclusion Options](#character-set-exclusion-options) for additional details and reference.)

> *Can also be accessed through any class engines using `<class engine>._generate_key`*

> *The ``<class engine>._generate_key`` method serves as the foundational backbone for the `generate_crypto_key` functionality.*
---

## Code Base
```python
@classmethod
def _generate_key(cls, *,
                  key_length: int = 32,
                  exclude: str = '', # Defaults to punctuation
                  include_all_chars: bool = False,
                  bypass_keylength: bool = False,
                  repeat: int = None) -> str:
```

- **Method Signature**: `_generate_key` is a class method, allowing it to be accessed through any class engines. It takes parameters such as `key_length`, `exclude`, `include_all_chars`, `bypass_keylength`, and `repeat`, providing customization options for key generation.
---

```python
    if all((exclude, include_all_chars)):
        raise CipherException(
            "Cannot specify both 'exclude' and 'include_all_chars' arguments."
        )
```

- **Conflict Check**: The method checks for conflicting arguments. If both `exclude` and `include_all_chars` are specified, it raises a `CipherException` to ensure proper usage.
---


```python
    if not bypass_keylength and \
            any((key_len < cls._MIN_KEYLENGTH,
                key_len > cls._MAX_KEYLENGTH)):
        raise CipherException(
                            f"key_length must be of value {cls._MIN_KEYLENGTH} <= x <= {cls._MAX_KEYLENGTH:_}.\n"
                            f'Specified Key Length: {key_len}'
                            )
```

- **Key Length Range Check**: Ensures that `key_length` falls within the specified range unless `bypass_keylength` is set to `True`.
---

```python
    threshold = cls._sig_larger(key_len, int(repeat_val))
    if not threshold.status:
        cls._MAX_TOKENS = threshold.threshold
        CipherException(
            "The specified values for 'key_length' or 'iterations' (repeat) exceeds the number of characters that can be cycled during repetition."
            f" Higher values for 'max_tokens' count is recommended for better results ('max_tokens' count is now {cls._MAX_TOKENS}).",
            log_method=logger.warning
            )
```

- **Token Threshold Calculation**: Calculates the threshold for generating tokens based on `key_length` and `repeat`. Adjusts `MAX_TOKENS` accordingly for better results.
---

```python
    slicer = lambda *args: ''.join(islice(*args, cls._MAX_TOKENS))
    all_chars = slicer(cycle(cls._ALL_CHARS))
    filtered_chars = cls._filter_chars(all_chars, exclude=punctuation)
```

- **Character Slicing**: Utilizes the `islice` function to slice characters based on the calculated `MAX_TOKENS`. Generates all available characters and filters them based on the exclusion list.

```python
    if include_all_chars:
        filtered_chars = all_chars
```

- **Include All Characters**: If `include_all_chars` is specified, the filtered characters are set to include all available characters.
    - **Exclude Characters**: If `exclude` is specified, it validates and filters characters based on the exclusion criteria.

```python
    if exclude:
        exclude_obj = cls._validate_object(exclude, type_is=str, arg='exclude_chars')
        filter_char = partial(cls._filter_chars, all_chars)
        exclude_type = cls._exclude_type(exclude_obj)
        filtered_chars = filter_char(exclude=exclude) if not exclude_type else \
                        filter_char(exclude=exclude_type)
```

- **Cryptographically Secure Randomized Key Generation**: Harnesses the cryptographic strength of `SystemRandom` to sample characters randomly from the filtered set, ensuring a secure and unpredictable key. The sampling is based on the minimum of `key_len` and the available characters, providing a robust foundation for cryptographic key generation.
```python
    passkey = SystemRandom().sample(
                    population=filtered_chars,
                    k=min(key_len, len(filtered_chars))
                    )
    encryption_key = ''.join(passkey)
```

## All Available Characters
- `ASCII letters`: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
- `Digits`: 0123456789
- `Punctuation`: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
- ~~`Whitespace`: '(space)\t\n\r\v\f'~~
    - ' ' (space), '\t' (tab), '\n' (newline), '\r' (carriage return), '\x0b' (vertical tab), '\x0c' (form feed)
    > *Please note that `Whitespace` is automatically excluded from all available options, as it can interfere with the encryption process and is not necessary or useful for cryptographic operations.*

## Character Set Exclusion Options
### Exclusion Chart
```python
{
    'digits': digits
    'punct': punctuation
    'ascii': ascii_letters
    'digits_punct': digits + punctuation,
    'ascii_punct': ascii_letters + punctuation,
    'digits_ascii': digits + ascii_letters,
    'digits_ascii_lower': digits + ascii_letters.lower(),
    'digits_ascii_upper': digits + ascii_letters.upper(),
    'punct_ascii_lower': punctuation + ascii_letters.lower(),
    'punct_ascii_upper': punctuation + ascii_letters.upper(),
    'ascii_lower_punct': ascii_letters.lower() + punctuation,
    'ascii_upper_punct': ascii_letters.upper() + punctuation,
    'digits_ascii_lower_punct': digits + ascii_letters.lower() + punctuation,
    'digits_ascii_upper_punct': digits + ascii_letters.upper() + punctuation
}
```

### Exclusion Examples
```python
crypto_key = generate_crypto_key(exclude=<str>)
crypto_key = (De)CipherEngine._generate_key(exclude=<str>)
```
- `digits`: *Excludes digits (0-9).*
    > ._@->htEqNvSv/_`a.+E-lJ)mzL("#~q
- `punct`: *Excludes punctuation characters.*
    > xXLyv16WONtWW1s8ri1lfF8suJzzHqSf
- `ascii`: *Excludes ASCII letters (both uppercase and lowercase).*
    > _\$9{92|66!6+)0<69{>},<*[/{_97_'
- `digits_punct`: *Excludes both digits and punctuation characters.*
    > NsLkBkXWlQgUQLsVYQeksbWKJqtOmxqZ
- `ascii_punct`: *Excludes both ASCII letters and punctuation characters.*
    > 14341403286159451993389011857514
- `digits_ascii`: *Excludes both digits and ASCII letters.*
    > *{[\[:=#,{_(-%#:*)](~&.~^@\.~:_@
- `digits_ascii_lower`: *Excludes both digits and lowercase ASCII letters.*
    > |UH[E&JF"HIIS#,,-|B#S\)D/+H|_(?\

- `digits_ascii_upper`: *Excludes both digits and uppercase ASCII letters.*
    > w$=q.`:_&,vvm<'s?++'i\`$o!|d@~(w

- `punct_ascii_lower`: *Excludes both punctuation characters and lowercase ASCII letters.*
    > UVME559NRTZKT3P7DEHS8ROOPTYA35BF

- `punct_ascii_upper`: *Excludes both punctuation characters and uppercase ASCII letters.*
    > ck05mdhi9a4csf1f4ejvru7p9kc5xpix

- `ascii_lower_punct`: *Excludes both lowercase ASCII letters and punctuation characters.*
    > Y2UJIEDBUO2AXD2SAET2QJL7LR6P776N

- `ascii_upper_punct`: *Excludes both uppercase ASCII letters and punctuation characters.*
    > f1021qygcqbzd6bfaac9ng9nitpehozy

- `digits_ascii_lower_punct`: *Excludes digits, lowercase ASCII letters, and punctuation characters.*
    > UHSTDQQZWVAHBFLMZYKUXIDXSTTPLQXE

- `digits_ascii_upper_punct`: *Excludes digits, uppercase ASCII letters, and punctuation characters.*
    > dhwzxoqzubwmrieyerpxrfttfeohacxl
---

# CipherEngine Class
## Overview
`CipherEngine` is a comprehensive Python library designed for encrypting and decrypting files and text data using symmetric key cryptography. It employs secure algorithms and encompasses features such as PBKDF2 key derivation, salt and iv generation, encryption header, and file integrity checks.

## Attributes

- `passkey`: The passphrase or key used for encryption (optional).
- `key_length`: The length of the cryptographic decipher key (default: 32).
- `iterations`: The number of iterations for key derivation.
- `exclude_chars`: Characters to exclude during passphrase generation (default: punctuation).
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

## Methods

- `encrypt_file()`: Encrypts a specified file.
- `encrypt_text()`: Encrypts a specified text.
- `quick_encrypt()`: Quickly encrypts text data and exports necessary information on-the-go.
    > **Back-bone for quick_ciphertext**

## Example
```python
cipher = CipherEngine(passkey='my_secret_key', iterations=1000)
cipher.encrypt_file()
```
---
# DecipherEngine Class

## Overview

The `DecipherEngine` class, an extension of the CipherEngine, is dedicated to decrypting data encrypted through the CipherEngine. It seamlessly operates with configuration files or NamedTuples generated by the CipherEngine during the encryption process.

## Attributes

- `ciphertuple` (NamedTuple): A NamedTuple containing details generated during the quick encryption process. It includes information such as the algorithm type, passkey, encrypted text, hash type, hash value, CPU power, original text, and salt value.
- `text` (Any | None): The encrypted text to be decrypted. This parameter represents the ciphertext obtained from the encryption process.
- `decipher_key` (Any | None): The decryption passphrase or key required to decrypt the encrypted text. It is crucial for the successful decryption of the provided ciphertext.
- `hash_value` (Any | None): The hash value of the original data. This value is used for integrity checking during the decryption process. It ensures that the decrypted text matches the original data, providing data integrity verification.
- `passkey_file`: str | Path: The path to the file containing the encryption details.
- `overwrite_file`: bool | None: Flag indicating whether to overwrite the original file during decryption (default: False).
- `verbose`: bool | None: Flag indicating whether to print verbose messages (default: False).


## Methods

- `decrypt_file()`: Decrypts an encrypted file.
- `decrypt_text()`: Decrypts encrypted text.
- `quick_decrypt()`: Quickly decrypts text data and exports necessary information on-the-go.
    > **Back-bone for quick_deciphertext**

## Example

```python
decipher = DecipherEngine(passkey_file='encrypted_file_passkey.ini')
decipher.decrypt_file()
```

# Class Engine Return State
### CipherTuple
- Every method in the `CipherEngine` and `DecipherEngine` classes yields a `NamedTuple` instance identified as `CipherTuple`. This intentional design choice simplifies referencing, offering a convenient means to manage and transmit the outcomes of cryptographic operations.
- This NamedTuple (`ciphertuple`) can be effortlessly employed within the corresponding classes, alleviating the requirement for explicit attribute specifications in subsequent cryptographic procedures. This design enhances usability and promotes a more streamlined cryptographic workflow.
---

# Usage Examples
### Import Module
```python
from cipher_engine import *
# __all__ = (
# 'CipherEngine', 'DecipherEngine',
# 'encrypt_file', 'decrypt_file',
# 'encrypt_text', 'decrypt_text',
# 'quick_ciphertext', 'quick_deciphertext',
# 'CipherException', 'generate_crypto_key',
# )
```
---
### Generate a Secure Cryptographic Key
```python
# Generate a cryptographic key using specified parameters
crypto_key = generate_crypto_key(key_length=int(1e5))
# Output: Mc2nTJ2zosmNxEu6cXF99lapaEEgWxjt....

crypto_key = generate_crypto_key(include_all_chars=True)
# Output: YGWm;2]-vLT*YS;My/mm5e\B[db$xfI

crypto_key = generate_crypto_key(exclude='digits_punct')
# Output: wmsjRLFxnVmXJfHGzjVNgWtRogZZQeGs
```
---

### Quickly Encrypt Text With Ease
```python
# Quick encryption of text data using CipherEngine.quick_encrypt
result_quick_ciphertext = quick_ciphertext(text='Hello, World!', export_passkey=False)
# Output: (NamedTuple)
# CipherTuple(algorithm_type='AES', decipher_key='546d746a556d746965555a464e6b4a5256553568563035584e466c4D62553172635735536355316e4D456f3d', encrypted_text='-----BEGIN CIPHERENGINE CRYPTOGRAPHIC ENCRYPTED KEY-----gAAAAABlnW67n3zkDLzoLzpTtpOVdrzKwXI5qNsqXOV8bFL34sYekvRwxAH4WciesqC3UPUBB8H7Gklm5GQdV12ZzElZrCEtEg==', hash_type='SHA512', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f', iterations=139239, iv_value=None, original_text='Hello, World!', salt_value=None)
```
---
### Quickly Decrypt Text With Ease
```python
result_quick_deciphertext = quick_deciphertext(ciphertuple=result_quick_ciphertext)
# Output: (NamedTuple)
# DecipherTuple(decrypted_text='Hello, World!', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f')

# Can also provide the attributes manually.
result_quick_deciphertext = quick_deciphertext(
    text=result_quick_ciphertext.encrypted_text,
    decipher_key='my_secret_key',
    hash_value='...'
)
```
---

### Encrypt Text using encrypt_text
```python
# Encrypt text using CipherEngine.encrypt_text
result_encrypt_text = encrypt_text(text='Hello, World!', key_length=32, export_path='output')
# Output: (NamedTuple)
# CipherTuple(algorithm_type='AES', decipher_key='4p8keHiYD5snme5DVUU8UuxKY2A9aFTc', encrypted_text='QKZrhffcL1TWS2J2fg==', hash_type='SHA512', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f', iterations=139239, iv_value='bbaf9031f11a2a7ac1a8e6384d73a874', original_text='Hello, World!', salt_value='ad12ab5e72028b16a77e03a0d4f7fce0')
```
---

### Decrypt text using decrypt_text
```python
# Decrypt text using DecipherEngine.decrypt_text
decrypt_text(ciphertuple=result_encrypt_text)
# Output: (NamedTuple)
# DecipherTuple(decrypted_text='Hello, World!', hash_value='dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f')
# Manually pass in attributes
result_decrypt_text = decrypt_text(
    passkey_file='output/info.ini',
    export_path='output/decrypted',
    overwrite_file=True
    )
```
---

### Encrypt a file using encrypt_file
```python
# Encrypt a file using CipherEngine.encrypt_file
result_encrypt_file = encrypt_file(
    file='test.txt',
    passkey=crypto_key,
    iterations=int(1e6),
    export_path='output')
# Output: (NamedTuple)
# CipherTuple(algorithm_type='AES', decipher_key='J]TTE~:vGzQ]E*?i;0br&!0,tY+zxSN^', encrypted_file='test.aes', hash_type='SHA512', hash_value='01e675506785122a5055d79a9e8fcb919c1b7838bd1d1209cd42ac67730d1f90', iterations=69619, iv_value='b26516ae7a074299bed53bbb92ebc34f', original_file='test.aes', salt_value='8cd661ff966f42fc8174623ff51e8bdd')
```
---

### Decrypt a file using decrypt_file
```python
# Decrypt a file using DecipherEngine.decrypt_file
= decrypt_file()
result_decrypt_file = decrypt_file(
    passkey_file='output/test_passkey.ini',
    overwrite_file=True)
# Output: (NamedTuple)
# DecipherTuple(decrypted_file=PosixPath('test.aes'), hash_value='5c0c10f62a2798b8f4f2cbb3d677fc9330d87250d3a1b27830ab050ba21c87ab')
```
---

# Command-Line Interface (CLI)
- The `CipherEngine` library offers a comprehensive CLI tool for seamless encryption and decryption of files and text data. This tool is designed to provide a user-friendly interface for the `CipherEngine` library, allowing users to leverage the library's powerful features with ease.
- The CLI tool is no longer in development and is readily accessible for utilization. For a comprehensive understanding of its functionalities, kindly refer to the [CLI-OPTIONS](./CLI-OPTIONS.md) documentation for additional details.
---

# Roadmap
## Upcoming Features
- **`Algorithm Selection`**: Empower users with the ability to choose their preferred encryption algorithm, tailoring the cryptographic process to their specific security preferences.
- **`Personal Unique Encryption Identifier`**: Provide users with the option to specify a personalized encryption header, allowing them to define a unique identifier according to their preferences, rather than relying on the default setting.
- **`Performance Optimization`**: Focus on optimizing performance to reduce computational overhead, particularly during encryption and decryption processes with higher iteration counts. These enhancements aim to streamline and expedite cryptographic operations for improved efficiency.
- **`CLI-Implementation`**: Integrate all cipher engine methods and features into a comprehensive CLI tool, allowing users to seamlessly encrypt and decrypt data from the command line.
> *This project is continuously evolving, and these features are anticipated to be implemented in future releases*

## Progress Table
- [ ] Algorithm Selection
- [ ] Personal Unique Encryption Identifier
- [ ] Performance Optimization
- [x] CLI-Implementation

>*The forthcoming features are crafted to enhance user flexibility and customization within the class engines, offering a personalized and tailored experience to accommodate diverse encryption needs. This tool prioritizes granting users autonomy over their encryption tools, guaranteeing effortless usage.*

---

# Contributors and Feedback

The `CipherEngine` project welcomes contributions from the community to enhance its features and reliability. If you are interested in contributing, please follow the guidelines below:

## Contributing

| Step | Action                                                                                    |
|------|-------------------------------------------------------------------------------------------|
| 1.   | Fork the repository on [GitHub](https://github.com/yousefabuz17/cipherengine) and clone it to your local machine.                                      |
| 2.   | Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature` or `git checkout -b bugfix/your-bug-fix`.                          |
| 3.   | Make your modifications and ensure that the code follows the project's coding standards.    |
| 4.   | Test your changes thoroughly to ensure they do not introduce any issues.                     |
| 5.   | Commit your changes with clear and concise messages: `git commit -m "Your informative commit message"`.                                               |
| 6.   | Push your branch to your fork on GitHub: `git push origin feature/your-feature`.             |
| 7.   | Open a pull request on the [main repository](https://github.com/yousefabuz17/cipherengine) with a detailed description of your changes.                |

## Feedback

Feedback is crucial for the improvement of the `CipherEngine` project. If you encounter any issues, have suggestions, or want to share your experience, please consider the following channels:

1. **GitHub Issues**: Open an issue on the [GitHub repository](https://github.com/yousefabuz17/cipherengine) to report bugs or suggest enhancements.

2. **Contact**: Reach out to the project maintainer via the following:
    - [Discord](https://discord.com/users/581590351165259793)
    - [Gmail](yousefzahrieh17@gmail.com)

> *Your feedback and contributions play a significant role in making the `CipherEngine` project more robust and valuable for the community. Thank you for being part of this endeavor!*

---
# Important Notes
## Maximum Iterations and Key Length
   - The maximum capacity for the number of iterations in encryption cycles for PBKDF2 and the key length is set to 1e8 (100 million).
        > *Caution is advised when utilizing this feature, as it may demand significant computational resources despite the code's efficiency.*
---

## Beta Release Status
   - This project is currently in beta release, demonstrating efficient functionality and consistent success in all conducted tests (pytest).
   - A comprehensive algorithm to guarantee the non-existence of specific files with default or specified names has not been extensively developed. This pertains to both encryption and decryption processes, contingent on parameters such as overwrite_file and file_name.
   - The verification of specified data for all methods incorporates an encryption identifier checking tool has only been implemented for `encrypt/decrypt` files at the moment.
---

## Critical Considerations for Optimal Usage
- After extensive testing and experimentation, this project can prove to be an invaluable tool when certain precautions are observed:
    - Properly storing the encrypted data's passkey files.
    - Refraining from making alterations on any files, including the passkey file, which is vital for the integrity of the encryption process.
        - It is important to note that encrypting the same file multiple times and decrypting it based on the number of times was achieved. However, it is pertinent to highlight that a bypass method to do so will not be implemented. It is essential to recognize that such practices may not enhance the security of the encryption and could potentially lead to severe data loss if not used correctly, particularly when employing identical encryption modes for relevant decryption processes.
> *In the event that an encryption identifier is detected at the beginning of the encrypted file during an encryption attempt, an error will be raised prior to further processing.*
---

# Risk Disclaimer

Ensuring the proper and secure handling of data is of paramount importance when employing the `CipherEngine` library. To minimize the risk of potential data loss, consider the following guidelines:

- **Backup File Parameter**: Always make use of the `backup_file` parameter to generate backups of your original files before initiating the encryption process. This provides an added layer of safety, allowing you to restore data in case of unexpected issues.

- **Imperfect Encryption**: It's essential to recognize that, despite robust encryption measures, no encryption method can be deemed entirely infallible. Under specific circumstances, encrypted data may still be susceptible to decryption. Be cognizant of the inherent limitations and complexities involved in cryptographic processes.

- **USE AT YOUR OWN RISK**: The author of the `CipherEngine` library holds no responsibility for any data loss that may occur during the usage of the library. Users are advised to exercise caution, adhere to best practices, and implement proper backup procedures to mitigate potential risks.

> *Exercise responsibility and vigilance in your usage of the library, keeping these considerations in mind. Understand that while the `CipherEngine` offers powerful encryption and decryption capabilities, it is not exempt from potential risks associated with the broader landscape of data security.*

---

# Conclusion

In summary, the `CipherEngine` project presents a versatile and robust framework for symmetric key cryptography. Discover the available classes and methods to seamlessly incorporate secure encryption and decryption functionality into your Python projects.