<img src="logo/cipher-engine-logo.jpg" alt="CipherEngine Logo" width="200"/> 

# CipherEngine 
[![PyPI version](https://badge.fury.io/py/cipher-engine.svg)](https://badge.fury.io/py/cipher-engine)
[![Downloads](https://pepy.tech/badge/cipher-engine)](https://pepy.tech/project/cipher-engine)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](https://opensource.org/license/apache-2-0/)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://github.com/yousefabuz17/CipherEngine/blob/main/README.md)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-blue.svg)](https://www.python.org/dev/peps/pep-0008/)
---
Welcome to `CipherEngine`, a powerful Python library dedicated to symmetric key cryptography. This documentation offers a detailed exploration of the library, highlighting key features, and practical usage examples. Please refer to the table of contents below to navigate through the documentation.

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
        - [Quick File Encryption](#quick-file-encryption)
        - [Quick Text Encryption](#quick-text-encryption)
        - [Basic File Encryption](#basic-file-encryption)
        - [Basic Text Encryption](#basic-text-encryption)
        - [AES Text Encryption](#aes-text-encryption)
    - [Data Integrity Assurance Mechanism](#data-integrity-assurance-mechanism)
- [Enhanced Security Measures](#enhanced-security-measures)
    - [Unique Encryption Identifiers](#unique-encryption-identifiers)
    - [Multiple Fernet Keys wit MultiFernet](#multiple-fernet-keys-wit-multifernet)
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
    - [Encrypt Text using encrypt_text](#encrypt-text-using-encrypt_text)
    - [Decrypt Text using decrypt_text](#decrypt-text-using-decrypt_text)
    - [Encrypt a File using encrypt_file](#encrypt-a-file-using-encrypt_file)
    - [Decrypt a File using decrypt_file](#decrypt-a-file-using-decrypt_file)
    - [Quickly Encrypt Files using quick_encrypt](#quickly-encrypt-files-using-quick_encrypt)
    - [Quickly Decrypt Files using quick_decrypt](#quickly-decrypt-files-using-quick_decrypt)
    - [Quickly Encrypt Text using quick_encrypt](#quickly-encrypt-text-using-quick_encrypt)
    - [Quickly Decrypt Text using quick_decrypt](#quickly-decrypt-text-using-quick_decrypt)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
- [Roadmap](#roadmap)
    - [Upcoming Features](#upcoming-features)
    - [Progress Table](#progress-table)
- [Contributors and Feedback](#contributors-and-feedback)
    - [Contributing](#contributing)
    - [Feedback](#feedback)
    - [Contact-Information](#contact-information)
- [Important Notes](#important-notes)
    - [Maximum Number of Fernet Keys](#maximum-number-of-fernet-keys)
    - [Beta Release Status](#beta-release-status)
    - [Critical Considerations for Optimal Usage](#critical-considerations-for-optimal-usage)
- [Risk Disclaimer](#risk-disclaimer)
- [Change-log](./CHANGELOG.md)
- [Conclusion](#conclusion)
---

# Requirements
- #### **`Python`**: ~=3.10
- #### **`cryptography`**: ~=41.0.4
- #### **`pycryptodome`**: ~=3.20.0
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
## Data Encryption and Decryption
- Securely encrypt and decrypt data (files/strings) using symmetric key cryptography, incorporating advanced security measures.
---

## Text Encryption and Decryption
- Effortlessly encrypt and decrypt text data, ensuring confidentiality with robust cryptographic techniques.

    > **`<class-engine>.(en/de)crypt_text`** - Rapidly encrypts and decrypts text data while providing essential information for seamless on-the-go operations.
---

## Passphrase Generation and Key Derivation
- Generate highly secure passphrases with customizable options to strengthen the foundation of your cryptographic keys.
- Utilizes advanced key derivation functions, including PBKDF2, to enhance the security of your cryptographic keys and protect against brute-force attacks.
    > *Refer to [Key Generation](#key-generation) for additional details.*
---

## Backup Management
- Opt for optional creation of backups for original files before encryption, offering a safety net for data preservation.
- Efficiently restore files to their original state during the decryption process if `overwrite_file` parameter is set to True.
---

## Export Passkey Configuration File
- Facilitates the exportation of the passkey configuration file into a distinct file, ensuring that sensitive information is handled with the utmost care.
- Offers the flexibility to choose any serialization formats for the exported passkey file.
    > *Default serialization is .cfg*
- The exported passkey file contains essential cryptographic details, including the passkey, hash value, and encryption identifiers, ensuring the secure management of cryptographic operations.
- The exported passkey file can be used for subsequent cryptographic operations, offering a convenient means to manage and transmit cryptographic details.
- The file can be easily shared with authorized personnel to facilitate secure decryption operations.
- The following encryption details are included in the exported passkey file:
    - `original_file`: The original file to be encrypted.
    - `encrypted_file`: The encrypted file.
    - `original_text`: The original text to be encrypted.
    - `encrypted_text`: The encrypted text.
    - `decipher_keys`: The Fernet keys used for decryption.
    - `(file_)hash_value`: The cryptographic hash value of the data.
    - `id1` and `id2`: The unique encryption identifiers.
    - `iterations`: The number of iterations for key derivation.
    - `passkey`: The passphrase used for encryption.
    - `r_and_p`: The number of rounds and parallelism for key derivation.
    - `salt_bytes_size`: The size of the salt bytes.
    - `salt_values`: The salt values used for key derivation.
    - `aes_iv`: The initialization vector for AES encryption.
    - `aes_passkey`: The passphrase used for AES encryption.
---

### Quick File Encryption
```
[CIPHER_INFO]
original_file = /Python/Projects/CipherEngine/tests/test_files/test_quick_engines.txt
encrypted_file = /Python/Projects/CipherEngine/tests/test_files/test_quick_engines.txt

[SECURITY_PARAMS]
hash_value = db740f4d0a400f6320b9af9efc30204c96b3b605ec68a41bb95efab93d755b1a882e1ddced0f48190153bf694fc43829ea58754ade52905ba17ae9ea78e5433f
passkey = ('quick_password', 'NjBjNGNiMjIzYjZkNDE2YWVlNTE0OGRhYzdhMjk5MjI=')

```

### Quick Text Encryption
```
[CIPHER_INFO]
original_text = testing quick engines.
encrypted_text = gAAAAABlwa-GqjyR5v1B2g1ukvlLM_aenXrLqeuyeRhVsBxjUtvqIsx6IMD7O-HmDvnvBOC4Z0nZJlS2kXaQX3vTqWjO53FT4_DyPzvW44o68RoJmCsC9j0=

[SECURITY_PARAMS]
hash_value = e77579463f45f559ca59f1ab19fdd62afd3fc9e261a2badd6e6a3c830df9e94468186407cbbdef4cae69941c16050e8dee7cc7425c4e5c2f5aec85033dca9030
passkey = ('quick_password', 'NjBjNGNiMjIzYjZkNDE2YWVlNTE0OGRhYzdhMjk5MjI=')

```

### Basic File Encryption
```
[CIPHER_INFO]
original_file = /Python/Projects/CipherEngine/tests/test_files/test_unencrypted_file.txt
encrypted_file = /Python/Projects/CipherEngine/tests/test_files/encrypted_test_unencrypted_file.aes

[SECURITY_PARAMS]
file_hash_value = 7be22ca40f8ebd9495e53d7951aaa0377a63239acfd071f0eaef34a1e4f7dc8879928c198b4c806ac5bcd93e6b67d6cba995b31fc4851b7eadc59682712f1acd
decipher_keys = ('500H3iVB-9YQVthE4yNaOGPG6KsreJw7RVYP0z74TfU=', 'fh4VSiKW8M8NlqU8Ty0Ba_WJakMNZdPlj9Bl0cuXU4c=')
hash_value = 7be22ca40f8ebd9495e53d7951aaa0377a63239acfd071f0eaef34a1e4f7dc8879928c198b4c806ac5bcd93e6b67d6cba995b31fc4851b7eadc59682712f1acd
id1 = -----BEGIN CIPHERENGINE ENCRYPTED KEY-----
id2 = -----END CIPHERENGINE ENCRYPTED KEY-----
iterations = 1024
passkey = ('cg284LfecTpV1cnK6kzz2ieIqZlHbADZ', '593263794f44524d5a6d566a564842574d574e75537a5a72656e6f796157564a6356707353474a4252466f3d')
r_and_p = (8, 1)
salt_bytes_size = 32
salt_values = ('732c5e2ea527a51e62adcddaac8cecb28befdf1e54f4919a2a8515f308dee97f', '732c5e2ea527a51e62adcddaac8cecb28befdf1e54f4919a2a8515f308dee97f')
```

### Basic Text Encryption
```
[CIPHER_INFO]
original_text = plaintext
encrypted_text = -----BEGIN CIPHERENGINE ENCRYPTED KEY-----gAAAAABlwVYhwuPX4KfRxjlN8a-_CQ-07mKvcB8pkUcZZNxD9BvBg0gIDsHtzYo5wq0aDGNba2X20sEzjUjeoZZyRE6_yuDDoQ==-----END CIPHERENGINE ENCRYPTED KEY-----

[SECURITY_PARAMS]
decipher_keys = ('zugxkADC_5-JGcXNX4gcK54bAjqWf3oCA6HuaEPolFY=', 'MXgml8ajCw_Lv_cmlw2ifNWKnEhHBmUt0O_PI_0-l9s=')
hash_value = d1b9457d6b063e86a2d85215f36fc98a301086adcd3c2a46748c8aad105a32939c0a203f4e67bafbf9a9b090db883d08f411297504b5625a3432b8876640c46a
id1 = -----BEGIN CIPHERENGINE ENCRYPTED KEY-----
id2 = -----END CIPHERENGINE ENCRYPTED KEY-----
iterations = 1024
passkey = ('133wCh1r6zxYJzKwugZgxVlKj48ITQ1u', '4d544d7a64304e6f4d584932656e685a536e704c6433566e576d6434566d784c616a5134535652524d58553d')
r_and_p = (8, 1)
salt_bytes_size = 32
salt_values = ('62eb790e2881edc5ba2b109e7f1ce1776ade245de62682373075d944f87f0536', '62eb790e2881edc5ba2b109e7f1ce1776ade245de62682373075d944f87f0536')
```

### AES Text Encryption
```
[CIPHER_INFO]
original_text = plaintext
encrypted_text = beginning_headergAAAAABlwa7J7ox_a2zllVoy_H_9ddqbZNVCzy9hF8_rDMD5zRDT8bwd9TWD6ljyNkBvPFvGN40dkwEze3YCN822mGvrk_0IT-dLZVDoZtF0Gd32FuInSag=ending_header

[SECURITY_PARAMS]
decipher_keys = ('zZs4QClkE0sdMLjdbecfR3s_jQ1DyYWUrwwg_0f7XCo=', 'WVnlnwA47R_LzC6DqccJ9dvX5r1FeV8dLX_2320DUaU=', 'Jp6vQZZYE2QEYiUv-7OrjG4kqjCV8BDCitKxqAFim4c=')
hash_value = d1b9457d6b063e86a2d85215f36fc98a301086adcd3c2a46748c8aad105a32939c0a203f4e67bafbf9a9b090db883d08f411297504b5625a3432b8876640c46a
id1 = beginning_header
id2 = ending_header
iterations = 1024
passkey = ('password123', '70617373776f7264313233')
r_and_p = (8, 1)
salt_bytes_size = 32
salt_values = ('44e42ea54cba9d473b51a3c6ce5a3768be6ecabc9a2088f6ea70af9d3632922f', '44e42ea54cba9d473b51a3c6ce5a3768be6ecabc9a2088f6ea70af9d3632922f', '44e42ea54cba9d473b51a3c6ce5a3768be6ecabc9a2088f6ea70af9d3632922f')
aes_iv = ab9e7e504095d382baf9f4d31e2b52ae
aes_passkey = ('AESpassword123', '3464663135303362623666613338656434626138616261306334633637653038')
```
---
### Data Integrity Assurance Mechanism

- **Cryptographic Hash Generation**: Upon the initial processing of a file or text string, the CipherEngine generates a unique cryptographic hash value for that specific data. This hash serves as a tamper-evident representation of the content, as any alterations to the data will result in a distinct hash value.
```python
    @classmethod
    def _calc_file_hash(cls, fp: P) -> str:
        file = cls._validate_file(fp)
        sha512_hash = SHA512.new()
        with open(fp, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha512_hash.update(chunk)
        return sha512_hash.hexdigest()

    @classmethod
    def _calc_str_hash(cls, string: str = None, encode=True) -> str:
        s = string if not encode else string.encode()
        return SHA512.new(data=s).hexdigest()
```

- **Cryptographic Hash Comparison**: The current hash value of the data is compared to the stored hash value in the passkey configuration file. Any disparities between these values indicate potential unauthorized changes to the data.
>*Additionally checks if the encrypted data starts and ends with the designated encryption identifier. This step ensures the correct application of encryption and further validates the data's integrity.*
---

# Enhanced Security Measures
## Overview
The `CipherEngine` library incorporates a wide range of security measures to ensure the confidentiality and integrity of your data. These measures include:

### Unique Encryption Identifiers
- Introduce a unique `identifiers` during encryption to enhance security and protect against potential vulnerabilities.
- This unique identifier that is generated during the encryption process and is appended to the beginning of the encrypted file. It is used to verify the integrity of the encrypted file during the decryption process, ensuring that the file has not been tampered with.
- The default `identifiers` is as follows:
    - *-----BEGIN CIPHERENGINE ENCRYPTED KEY-----*
    - *-----END CIPHERENGINE ENCRYPTED KEY-----*

### Multiple Fernet Keys with MultiFernet
- **`MultiFernet`** is a class that allows for the combination of multiple `Fernet` keys into a single key. This class is used to generate a unique key for each encryption process, ensuring that the same key is not used for multiple encryption processes.
- **`Fernet`** is a class that offers symmetric encryption based on the AES algorithm in CBC mode with a 128-bit key for encryption and HMAC for authentication. It is used to encrypt and decrypt data, ensuring confidentiality and integrity.

### Scrypt Key Derivation Function
- The `CipherEngine` library employs the scrypt Key Derivation Function (KDF) for secure key derivation. This enhances the security of cryptographic operations by deriving a key from a passphrase.
- The scrypt KDF is a key derivation function designed to be secure against hardware attacks and is well-suited for password-based key derivation.

### Advanced Encryption Algorithms
- The `CipherEngine` library provides support for advanced encryption algorithms, including:
  - **SHA512 Hashing**: The SHA512 algorithm is employed for secure cryptographic hashing.
  - **AES Encryption**: Utilizes the AES algorithm for strong encryption.
  - **Padding and Unpadding**: Implements padding and unpadding techniques to ensure data integrity.

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
def _generate_key(cls, 
                *,
                key_length: int = 32,
                exclude: str = "", # Defaults to punctuation
                include_all_chars: bool = False,
                bypass_keylength: bool = False,
                repeat: int = None,
                urlsafe_encoding: bool = False) -> str:
```

- **Method Signature**: `_generate_key` is a class method, allowing it to be accessed through any class engines. It takes parameters such as `key_length`, `exclude`, `include_all_chars`, `bypass_keylength`, `repeat`, and `urlsafe_encoding` providing customization options for key generation.
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
if not bypass_keylength and key_length < cls._MAX_KEYLENGTH:
    raise CipherException(
        f"For security reasons, the passkey must have a length of at least {cls._MAX_KEYLENGTH} characters. "
        "If a shorter key is desired, provide a 'bypass_keylength' parameter."
    )
too_large = any(
            (repeat_val > cls._MAX_CAPACITY, key_length > cls._MAX_CAPACITY)
        )
if too_large:
    if not bypass_keylength:
        raise CipherException(
            f"The specified counts surpasses the computational capacity required for {cls.__name__!r}. "
            "It is recommended to use a count of 32 <= x <= 512, considering the specified 'key_length'."
            f"\nMax Capacity: {cls._MAX_CAPACITY:_}"
            f"\nCharacter Repeat Count: {repeat_val:_}"
        )
    elif bypass_keylength:
        CipherException(
            "The specified count(s) indicate a potentially high magnitude. "
            "Please take into account the substantial computational resources that may be required to process such large values.",
            log_method=logger.info,
        )
```

- **Key Length Range Check**: Ensures that `key_length` falls within the specified range unless `bypass_keylength` is set to `True`.
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
- `Hexdigits`: 0123456789abcdefABCDEF
- `Punctuation`: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
- ~~`Whitespace`: '(space)\t\n\r\v\f'~~
    - ' ' (space), '\t' (tab), '\n' (newline), '\r' (carriage return), '\x0b' (vertical tab), '\x0c' (form feed)
    > *Please note that `Whitespace` is automatically excluded from all available options. Its inclusion could disrupt the encryption process when exporting data to a configuration file and is unnecessary for cryptographic operations.**

## Character Set Exclusion Options
### Exclusion Chart
```python
{
    "punct": punctuation,
    "ascii": ascii_letters,
    "ascii_lower": ascii_lowercase,
    "ascii_upper": ascii_uppercase,
    "ascii_punct": ascii_letters + punctuation,
    "ascii_lower_punct": ascii_lowercase + punctuation,
    "ascii_upper_punct": ascii_uppercase + punctuation,
    "digits": digits,
    "digits_ascii": digits + ascii_letters,
    "digits_punct": digits + punctuation,
    "digits_ascii_lower": digits + ascii_lowercase,
    "digits_ascii_upper": digits + ascii_uppercase,
    "digits_ascii_lower_punct": digits + ascii_lowercase + punctuation,
    "digits_ascii_upper_punct": digits + ascii_uppercase + punctuation,
    "hexdigits": hexdigits,
    "hexdigits_punct": hexdigits + punctuation,
    "hexdigits_ascii": hexdigits + ascii_letters,
    "hexdigits_ascii_lower": hexdigits + ascii_lowercase,
    "hexdigits_ascii_upper": hexdigits + ascii_uppercase,
    "hexdigits_ascii_punct": hexdigits + punctuation,
    "hexdigits_ascii_lower_punct": hexdigits + ascii_lowercase + punctuation,
    "hexdigits_ascii_upper_punct": hexdigits + ascii_uppercase + punctuation,
}
```

### Exclusion Examples
```python
crypto_key = generate_crypto_key(exclude=<str>)
# Alternatively, generate a key using any of the class engines.
crypto_key = <class-engine>._generate_key(exclude=<str>)
```
- `punct`: *Excludes punctuation characters.*
    > xXLyv16WONtWW1s8ri1lfF8suJzzHqSf
- `ascii`: *Excludes ASCII letters (both uppercase and lowercase).*
    > _\$9{92|66!6+)0<69{>},<*[/{_97_'
- `ascii_lower`: *Excludes lowercase ASCII letters.*
    > B\#F+=KE<9(DPDQ|)~5ALP,V//*4S>\=
- `ascii_upper`: *Excludes uppercase ASCII letters.*
    > guzgs5[6(9["(8d8k[g,7=$8?-9i{^*)
- `ascii_punct`: *Excludes all ASCII letters and punctuations.*
    > 22947751028796725748955353648359
- `ascii_lower_punct`: *Excludes both lowercase ASCII letters and punctuation characters.*
    > Y2UJIEDBUO2AXD2SAET2QJL7LR6P776N
- `ascii_upper_punct`: *Excludes both uppercase ASCII letters and punctuation characters.*
    > f1021qygcqbzd6bfaac9ng9nitpehozy
- `digits`: *Excludes all digits.*
    > ._@->htEqNvSv/_`a.+E-lJ)mzL("#~q
- `digits_ascii`: *Excludes both digits and ASCII letters.*
    > *{[\[:=#,{_(-%#:*)](~&.~^@\.~:_@
- `digits_punct`: *Excludes both digits and punctuation characters.*
    > NsLkBkXWlQgUQLsVYQeksbWKJqtOmxqZ
- `digits_ascii_lower`: *Excludes both digits and lowercase ASCII letters.*
    > |UH[E&JF"HIIS#,,-|B#S\)D/+H|_(?\
- `digits_ascii_upper`: *Excludes both digits and uppercase ASCII letters.*
    > w$=q.`:_&,vvm<'s?++'i\`$o!|d@~(w
- `digits_ascii_lower_punct`: *Excludes digits, lowercase ASCII letters, and punctuation characters.*
    > UHSTDQQZWVAHBFLMZYKUXIDXSTTPLQXE
- `digits_ascii_upper_punct`: *Excludes digits, uppercase ASCII letters, and punctuation characters.*
    > dhwzxoqzubwmrieyerpxrfttfeohacxl
- `hexdigits`: *Excludes hexdigit characters*
    > |;gMWX;P\UuuN^\k{m|x=~hMOR}<[H=-
- `hexdigits_punct`: *Excludes hexdigits and punctuation characters.*
    > jXnVVJxHtPSlTHytKiNYGslRisrypIoo
- `hexdigits_ascii`: *Excludes hexdigits and ASCII letters.*
    > .":"&.&`!_.*@]*'+-<}+~<<,~!~_,~>
- `hexdigits_ascii_lower`: *Excludes hexdigits and lowercase ASCII characters.*
    > #OW_R>R;UJ;J@U#X'=:+>TIQ+}{K@S|U
- `hexdigits_ascii_upper`: *Excludes hexdigits and uppercaseASCII characters.*
    > [+y/.]*?ls\$jh\r!gy<^or%j)l~:w!'
- `hexdigits_ascii_lower_punct`: *Excludes hexdigits and lowercase ASCII letters and punctuation characters.*
    > XHYMPXJLPXOOMYSYYGWRYYNUXYPTZRRT
- `hexdigits_ascii_upper_punct`: *Excludes hexdigits and uppercase ASCII letters and punctuation characters.*
    > xjhvyqswzjoopqnnghwzntioryothxil
---

# CipherEngine Class
## Overview
`CipherEngine` is a comprehensive Python library designed for encrypting and decrypting files and text data using symmetric key cryptography. It employs secure algorithms and encompasses features `Fernet` and `MultiFernet`, encryption headers, and file/text integrity checks.

## Attributes

- `file`: str | Path | None: The file to be processed and encrypted.
- `text`: str | None: The text to be processed and encrypted.
- `file_name`: str | None: The name of the file containing the encryption details.
- `passkey`: str | int | None: The passphrase or integer to be used for encryption (default: None).
- `gui_passphrase`: bool: Flag indicating whether to use GUI for passphrase entry (default: False).
- `num_of_salts`: int: Number of `Fernet` keys to be generated and processed with `MultiFernet`.
- `export_path`: Path | None: The path where exported files will be stored (default: None).
- `export_passkey`: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
- `serializer`: str | None: The type of serialization to be used for exporting the passkey file ('json' or 'ini').
- `iterations`: int | None: The number of iterations for key derivation (default: None).
- `min_power`: bool: Flag indicating whether to enforce minimum passphrase strength (default: False).
- `max_power`: bool: Flag indicating whether to enforce maximum passphrase strength (default: False).
- `advanced_encryption`: bool: Flag indicating whether to use advanced encryption features (default: False).
- `special_keys`: bool | None: If True, uses CipherEngine's custom cryptographic key generation, otherwise uses default keys generated from `Fernet` (default: None).

## Cryptographic Attributes:
- `key_length`: int: The desired key length for Fernet encryption (default: 32).
- `bypass_keylength`: bool: Flag indicating whether to bypass key length validation (default: False).
- `include_all_chars`: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
- `exclude_chars`: str | None: Characters to exclude during passphrase generation (default: None).


---

## Methods
- `encrypt_file()`: Encrypts a specified file.
- `encrypt_text()`: Encrypts a specified text.
- `quick_encrypt()`: Encrypts a specified text using only `Fernet`.

## Example
```python
cipher = CipherEngine(passkey='my_secret_key', num_of_keys=50)
cipher.encrypt_file()
```
---
# DecipherEngine Class

## Overview

The `DecipherEngine` class, an extension of the CipherEngine, is dedicated to decrypting data encrypted through the CipherEngine. It seamlessly operates with configuration files or NamedTuples generated by the CipherEngine during the encryption process.

## Attributes

- `ciphertuple` (NamedTuple): A NamedTuple containing details generated during the quick encryption process. It includes information such as the algorithm type, passkey, encrypted text, hash type, hash value, CPU power, original text, and salt value.
- `passkey_file`: str | Path: The path to the file containing the encryption details.
- `overwrite_file`: bool | None: Flag indicating whether to overwrite the original file during decryption (default: False).
- `manual_kwgs`: dict: Dictionary containing encryption data to be used for decryption.


## Methods

- `decrypt_file()`: Decrypts an encrypted file.
- `decrypt_text()`: Decrypts encrypted text.
- `quick_decrypt()`: Quickly decrypts text data and exports necessary information on-the-go.

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
    # "METADATA",
    # "CipherEngine",
    # "DecipherEngine",
    # "CipherException",
    # "generate_crypto_key",
    # "encrypt_file",
    # "decrypt_file",
    # "encrypt_text",
    # "decrypt_text",
    # "quick_encrypt",
    # "quick_decrypt",
)
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

### Encrypt Text using encrypt_text
```python
# Encrypt text using CipherEngine.encrypt_text
result_encrypt_text = encrypt_text(text='Hello, World!', num_of_keys=20, export_path='output')
# Output: (NamedTuple)
CipherTuple(original_text='hello', encrypted_text='-----BEGIN CIPHERENGINE ENCRYPTED KEY-----gAAAAABlwcnmXXDioh1crkkbEwmY5qBe6Qun0_qzXZefWcAwxhqbAsw8giX0m6Tx4LXcv9fFOhILuwX9ROFeQD_4zgXToU72jw==-----END CIPHERENGINE ENCRYPTED KEY-----', decipher_keys=('6jzNzRksHQnv3MzzoLADhtHppSPK2WCQd420mlirsEw=', 'M8nD8Z9gHs5Qug15GIws09bP2zi18c_XWdwx5DlOKvg='), hash_value='9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043', id1='-----BEGIN CIPHERENGINE ENCRYPTED KEY-----', id2='-----END CIPHERENGINE ENCRYPTED KEY-----', iterations=1048576, passkey=('R5yQK8BwvNWEsDRsxMuN8zuooVryjLxk', '556a563555557334516e6432546c6446633052536333684e64553434656e567662315a796557704d6547733d'), r_and_p=(8, 1), salt_bytes_size=32, salt_values=('bf0318472989375bdcc6ee565f488a81c44b0bc2d9466e33a4412872d49b89c0', 'bf0318472989375bdcc6ee565f488a81c44b0bc2d9466e33a4412872d49b89c0'))
```
---

### Decrypt text using decrypt_text
```python
# Decrypt text using DecipherEngine.decrypt_text
decrypt_text(ciphertuple=result_encrypt_text)
# Alternatively, can pass in the attributes manually
result_decrypt_text = decrypt_text(
    passkey_file='output/info.ini',
    export_path='output/decrypted',
    overwrite_file=True
    )
# Output: (NamedTuple)
DecipherTuple(decrypted_text='unencrypted-text', hash_value='9deabffbf5b50efd1f9b75133edf33d00372599babfef5dd9d1fa5425610ad6643c03b4f5ea6c32b7d8ec5f1891de6c297f1a04a3344f7e16c497354ce7736a6')
```
---

### Encrypt a file using encrypt_file
```python
# Encrypt a file using CipherEngine.encrypt_file
result_encrypt_file = encrypt_file(
    file='test.txt',
    overwrite_file=False,
    export_path='output')
# Output: (NamedTuple)
CipherTuple(original_file=PosixPath('test.txt'), encrypted_file=PosixPath('encrypted_test.aes'), file_hash_value='04ca92b5d6deaae50d209010ed4bd2a5299b527b2a878218bde3ee5bbf782b38471df2db2822b18a768af8d65cb93428ff2a4312da8e8339a5f0272d67e2e191', decipher_keys=('kY7w1vAXB8RJ_4FpfymtSP1u5LPhBFk-FNHtv_7RYgM=', 'awH-KMrjB47xinZ3hd_QsKe80vU1hwIivNNYQYbuXdQ='), hash_value='04ca92b5d6deaae50d209010ed4bd2a5299b527b2a878218bde3ee5bbf782b38471df2db2822b18a768af8d65cb93428ff2a4312da8e8339a5f0272d67e2e191', id1='-----BEGIN CIPHERENGINE ENCRYPTED KEY-----', id2='-----END CIPHERENGINE ENCRYPTED KEY-----', iterations=1024, passkey=('ozoGWjOqDxQ55qcV5J1VUOFMLrVQiMOS', '623370765231647154334645654645314e58466a566a564b4d565a5654305a4e54484a5755576c4e54314d3d'), r_and_p=(8, 1), salt_bytes_size=32, salt_values=('8333f1ef6079337e3c60c2aff72fc544ad2efc9349c17b891484dabc9b3501cf', '8333f1ef6079337e3c60c2aff72fc544ad2efc9349c17b891484dabc9b3501cf'))
```
---

### Decrypt a file using decrypt_file
```python
# Decrypt a file using DecipherEngine.decrypt_file
result_decrypt_file = decrypt_file(
    passkey_file='output/test_passkey.ini',
    overwrite_file=False)
# Output: (NamedTuple)
DecipherTuple(decrypted_file=PosixPath('decrypted_encrypted_test.dec'), hash_value='04ca92b5d6deaae50d209010ed4bd2a5299b527b2a878218bde3ee5bbf782b38471df2db2822b18a768af8d65cb93428ff2a4312da8e8339a5f0272d67e2e191')
```

### Quickly Encrypt Files using quick_encrypt
```python
quick_encrypt(file="test.aes")
# Output: (NamedTuple)
QCipherTuple(original_file=PosixPath('test.aes'), encrypted_file=PosixPath('encrypted_test.aes'), hash_value='04ca92b5d6deaae50d209010ed4bd2a5299b527b2a878218bde3ee5bbf782b38471df2db2822b18a768af8d65cb93428ff2a4312da8e8339a5f0272d67e2e191', passkey=('yuQYlxGuDSG97YSdzDOZvOrjq88gfOnb', 'OWIxN2RkOThhM2I1ZjVhMzA2MTVlYzlhYTA3NDA3NDM='))
```

### Quickly Decrypt Files using quick_decrypt
```python
quick_decrypt(ciphertuple=a)
# Output: (NamedTuple)
QDecipherTuple(decrypted_file=PosixPath('encrypted_test.aes'), hash_value='04ca92b5d6deaae50d209010ed4bd2a5299b527b2a878218bde3ee5bbf782b38471df2db2822b18a768af8d65cb93428ff2a4312da8e8339a5f0272d67e2e191')
```

### Quickly Encrypt Text using quick_encrypt
```python
quick_encrypt(text="unencrypted-text")
# Output: (NamedTuple)
QCipherTuple(original_text='unencrypted-text', encrypted_text='gAAAAABlwcvyACkfYqf3Zw1ShY2MpNwnAA9eZSa0phLlOuFYy1F-26ExIRuCowaSnbFxIr9TKCnSAnYccO9TH2595ez0sGboS57XP4AFAU9xh5gDtac7UOU=', hash_value='9deabffbf5b50efd1f9b75133edf33d00372599babfef5dd9d1fa5425610ad6643c03b4f5ea6c32b7d8ec5f1891de6c297f1a04a3344f7e16c497354ce7736a6', passkey=('AzgV81oCpXe8G9apFs3PqY9vCgBAwacu', 'ZjFkOWUyYmNkOTYyMjFhZWIwZTQwZmQ0OWNmMWU3NGU='))
```

### Quickly Decrypt Text using quick_decrypt
```python
quick_decrypt(ciphertuple=a)
# Output: (NamedTuple)
QDecipherTuple(decrypted_text='unencrypted-text', hash_value='9deabffbf5b50efd1f9b75133edf33d00372599babfef5dd9d1fa5425610ad6643c03b4f5ea6c32b7d8ec5f1891de6c297f1a04a3344f7e16c497354ce7736a6')
```
---

# Command-Line Interface (CLI)
- The `CipherEngine` library offers a comprehensive CLI tool for seamless encryption and decryption of files and text data. This tool is designed to provide a user-friendly interface for the `CipherEngine` library, allowing users to leverage the library's powerful features with ease.
- The CLI tool is no longer in development and is readily accessible for utilization. For a comprehensive understanding of its functionalities, kindly refer to the [CLI-OPTIONS](./CLI-OPTIONS.md) documentation for additional details.
---

# Roadmap
## Upcoming Features
- ~~**`Personal Unique Encryption Identifier`**: Provide users with the option to specify a personalized encryption header, allowing them to define a unique identifier according to their preferences, rather than relying on the default setting.~~
- **`Performance Optimization`**: Focus on optimizing performance to reduce computational overhead, particularly during encryption and decryption processes with higher iteration counts. These enhancements aim to streamline and expedite cryptographic operations for improved efficiency.
- ~~**`CLI-Implementation`**: Integrate all cipher engine methods and features into a comprehensive CLI tool, allowing users to seamlessly encrypt and decrypt data from the command line.~~
> *This project is continuously evolving, and these features are anticipated to be implemented in future releases*

## Progress Table
- [x] Implement quick ciphers using only Fernet
- [x] Implement AES encryption
- [x] Personal Unique Encryption Identifier
- [x] Performance Optimization
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
### Contact Information
    - [Discord](https://discord.com/users/581590351165259793)
    - [Gmail](yousefzahrieh17@gmail.com)

> *Your feedback and contributions play a significant role in making the `CipherEngine` project more robust and valuable for the community. Thank you for being part of this endeavor!*

---
# Important Notes
## Maximum Number of Fernet Keys
- The maximum number of Fernet keys that can be generated is unrestristed. However, it is important to note that the number of keys generated is directly proportional to the time required for encryption and decryption processes. Therefore, it is recommended to generate a reasonable number of keys to ensure optimal performance.
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