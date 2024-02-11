"""
# CipherEngine

This module provides functions for cryptographic key generation, \
encryption and decryption for text and files using \
the `Fernet` symmetric key cryptography library, `MultiFernet` and `AES`.

### Functions:
    - `generate_crypto_key(**kwargs) -> str`: Generates a cryptographic key based on specified parameters.
    - `encrypt_file(**kwargs) -> NamedTuple`: Encrypts a file and returns information about the process.
    - `decrypt_file(**kwargs) -> NamedTuple`: Decrypts a file using encryption details from a previous process.
    - `encrypt_text(**kwargs) -> NamedTuple`: Encrypts text and returns information about the process.
    - `decrypt_text(**kwargs) -> NamedTuple`: Decrypts text using encryption details from a previous process.
    - `quick_encrypt(**kwargs) -> NamedTuple`: Quickly encrypts text and/or files using only a passkey and `Fernet`.
    - `quick_decrypt(**kwargs) -> NamedTuple`: Quickly decrypts text and/or files using only a passkey and `Fernet`.

### Important Notes:
    - The `generate_crypto_key` function allows customization of key generation parameters.
    - The `encrypt_file` and `decrypt_file` functions provide file encryption and decryption capabilities.
    - The `encrypt_text` and `decrypt_text` functions handle encryption and decryption of text data.
    - The `quick_encrypt` and `quick_decrypt` functions handle encryption and decryption of text and/or files data.

### Cryptographic Attributes:
    - Various parameters such as `num_of_salts`, `include_all_chars`, `exclude_chars`, and `special_keys` \
        customize the cryptographic operations during key and text generation.

### Exception Handling:
    - The module raises a `CipherException` with specific messages for various error scenarios.

For detailed information on each function and its parameters, refer to the individual docstrings \
or documentations.
"""


import ast
import os
import re
import math
import json
import psutil
import secrets
import operator
import inspect
import base64
import shutil
import logging
import operator
import configparser
import numpy as np
import tkinter as tk
from tkinter import simpledialog
from pathlib import Path
from logging import Logger
from datetime import datetime
from functools import partial, wraps
from itertools import cycle, islice, tee, chain
from dataclasses import dataclass, field
from collections import OrderedDict, namedtuple
from concurrent.futures import ThreadPoolExecutor
from string import (
    digits,
    hexdigits,
    punctuation,
    ascii_letters,
    ascii_lowercase,
    ascii_uppercase,
    whitespace,
)
from typing import (
    Any,
    AnyStr,
    Iterable,
    NamedTuple,
    TypeVar,
    Optional,
    Iterator,
    overload,
    Union,
    NoReturn,
)
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from cryptography.fernet import Fernet, MultiFernet, InvalidToken


def get_logger(
    *,
    name: str = __name__,
    level: int = logging.DEBUG,
    formatter_kwgs: dict = None,
    handler_kwgs: dict = None,
    mode: str = "a",
    write_log: bool = True,
) -> Logger:
    logging.getLogger().setLevel(logging.NOTSET)
    _logger = logging.getLogger(name)

    if logging.getLevelName(level):
        _logger.setLevel(level=level)

    file_name = Path(__file__).with_suffix(".log")
    _formatter_kwgs = {
        **{
            "fmt": "[%(asctime)s][LOG %(levelname)s]:%(message)s",
            "datefmt": "%Y-%m-%d %I:%M:%S %p",
        },
        **(formatter_kwgs or {}),
    }
    _handler_kwgs = {**{"filename": file_name, "mode": mode}, **(handler_kwgs or {})}

    formatter = logging.Formatter(**_formatter_kwgs)

    if write_log or level == logging.DEBUG:
        stream_handler = logging.FileHandler(**_handler_kwgs)
    else:
        stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    _logger.addHandler(stream_handler)
    return _logger


logger = get_logger(level=logging.INFO, write_log=True)
P = TypeVar("P", Path, str)


class CipherException(BaseException):
    def __init__(self, *args, log_method=logger.critical):
        self.log_method = log_method
        super().__init__(*args)
        self.log_method(*args)


@dataclass(kw_only=True)
class _BaseCryptoEngine:
    """
    Base crypotgraphic class for the CipherEngine hierarchy, providing common attributes and functionality \
    for generating cryptographic keys, salt values, and RSA key pairs.
    """

    num_of_salts: int = field(repr=False, default=None)
    r: int = field(repr=False, default=8)
    p: int = field(repr=False, default=1)
    salt_bytes_size: int = field(repr=False, default=None)
    aes_passkey: Optional[Union[str, int]] = field(repr=False, default=None)
    exclude_chars: str = field(repr=False, default=None)
    include_all_chars: Optional[bool] = field(repr=False, default=False)
    _AES_KSIZES: tuple[int] = AES.key_size
    _AES_BSIZE: int = AES.block_size
    _PKCS_VALUE: int = 8
    _MAX_TOKENS = int(1e5)
    _MAX_KEYLENGTH: int = 32
    _ALL_CHARS: str = digits + ascii_letters + punctuation
    _WHITESPACE: str = whitespace
    _MAX_CAPACITY: int = 2**32
    _EXECUTOR: ThreadPoolExecutor = ThreadPoolExecutor()

    def _validate_numsalts(cls, nsalt: int) -> int:
        if nsalt:
            num_salt = cls._validate_object(nsalt, type_is=int, arg="Number of Salts")
            if num_salt >= cls._MAX_TOKENS:
                CipherException(
                    f"The specified 'num_of_salts' surpasses the recommended limit for {MultiFernet.__name__}. "
                    "Adding a large number of salts for key deriviation can result in computatonal power. "
                    "It is recommended to keep the number of keys within 2 <= x <= 5 "
                    "for efficient key rotation and optimal performance.\n"
                    f"Specified Amount: {num_salt:_}\n"
                    f"Recommended Amount: 2",
                    log_method=logger.warning,
                )
            return num_salt
        else:
            raise CipherException(
                "Number of keys to be generated must be of value >=1. "
                f"The specified value is considered invalid ({nsalt})"
            )

    @staticmethod
    def _base64_key(__key: str, base_type="encode") -> Union[bytes, None]:
        base = [base64.urlsafe_b64decode, base64.urlsafe_b64encode][
            base_type == "encode"
        ]
        try:
            return base(__key)
        except AttributeError as attr_error:
            raise CipherException(
                f"Failed to derive encoded bytes from {__key!r}. " f"\n{attr_error}"
            )

    @property
    def salt_size(self):
        return (
            self._validate_object(
                self.salt_bytes_size, type_is=int, arg="Salt Bytes Size"
            )
            or 32
        )

    @staticmethod
    def _gen_random(__size: int = 16) -> bytes:
        return secrets.token_bytes(__size)

    @property
    def gen_salts(self) -> Union[str, bytes]:
        if self.num_of_salts:
            self.num_of_salts = self._validate_numsalts(self.num_of_salts)
        else:
            self.num_of_salts = 2

        if self.salt_bytes_size:
            self.salt_bytes_size = self._validate_object(
                self.salt_bytes_size, type_is=int, arg="Salt Bytes"
            )
        else:
            self.salt_bytes_size = 32
        return (
            self._gen_random(self.salt_bytes_size)
            for _ in range(1, self.num_of_salts + 1)
        )

    @property
    def aes_bits(self):
        return self._gen_random(self._AES_BSIZE)

    @property
    def block_size(self):
        if not self._validate_object(self.r, type_is=int, arg="Block Size"):
            raise CipherException(
                "The specified block size must be a positive integer greater than 1."
            )
        else:
            self.r = 8
        return abs(self.r)

    @classmethod
    def _char_checker(cls, original_text: str, raise_exec=False) -> bool:
        checker = all(char in cls._ALL_CHARS for char in original_text)
        if raise_exec and not checker:
            raise CipherException(
                "The specified passkey does not meet the required criteria and contains illegal characters which cannot be utilized for security reasons.\n"
                f"Illegal passphrase: {original_text!r}"
            )
        if cls._validate_object(original_text, type_is=str, arg="Text"):
            return checker

    @classmethod
    def _get_fernet(cls, encoded_keys=None, fernet_type=MultiFernet) -> Any:
        if fernet_type is Fernet:
            return Fernet(encoded_keys)
        return MultiFernet(tuple(encoded_keys))

    @staticmethod
    def _validate_object(
        __obj: Any, type_is: type = int, arg: str = "Argument"
    ) -> int | str | tuple[str] | Path:
        """
        Validate and coerce the input object to the specified type.

        Parameters:
        - __obj (Any): The input object to be validated and coerced.
        - type_is (Type[Any]): The target type for validation and coercion.
        - arg (str): A descriptive label for the argument being validated.

        Returns:
        - Any: The validated and coerced object.

        Raises:
        - CipherException: If validation or coercion fails.

        """

        if not __obj:
            return

        possible_instances = (TypeError, ValueError, SyntaxError)

        if type_is is Any:
            type_is = type(__obj)

        if type_is in (int, float):
            try:
                _obj = abs(int(__obj))
            except possible_instances:
                raise CipherException(
                    f"{arg!r} must be of type {int} or integer-like {str}. "
                    f"{__obj!r} is an invalid argument."
                )
        elif type_is is str:
            try:
                _obj = str(__obj)
            except possible_instances:
                raise CipherException(f"{arg!r} must be of type {str}")
        elif type_is is Iterable and isinstance(__obj, (list, tuple, Iterable)):
            try:
                _obj = tuple(map(str, __obj))
            except possible_instances:
                raise CipherException(
                    f"{arg!r} must be of type {list} with {int} or integer-like {str}"
                )
        elif type_is is Path:
            try:
                _obj = Path(__obj)
            except possible_instances:
                raise CipherException(f"{arg!r} must be of type {str} or {Path}")
        else:
            raise CipherException(
                f"{__obj}'s type is not a valid type for this method."
            )

        return _obj

    @classmethod
    def _filter_chars(cls, __string: str, *, exclude: str = "") -> str:
        """
        ### Filter characters in the given string, excluding those specified.

        #### Parameters:
            - `__string` (str): The input string to be filtered.
            - `exclude` (str): Characters to be excluded from the filtering process.

        #### Returns:
            - str: The filtered string with specified characters excluded.

        #### Notes:
            - This method employs the `translate` method to efficiently filter characters.
            - Whitespace ('(space)\t\n\r\v\f') characters are automatically excluded as they can inadvertently impact the configuration file.
            - To exclude additional characters, provide them as a string in the `exclude` parameter.
        """
        check_str = cls._validate_object(__string, type_is=str, arg="Char")
        exclude = cls._validate_object(exclude, type_is=str, arg="Exclude Chars")
        full_string = "".join(check_str)
        filter_out = cls._WHITESPACE + exclude
        string_filtered = full_string.translate(str.maketrans("", "", filter_out))
        return string_filtered

    @staticmethod
    def _exclude_type(
        __key: str = "punct", return_dict: bool = False
    ) -> Union[str, None]:
        """
        ### Exclude specific character sets based on the provided key.

        #### Parameters:
        - __key (str): The key to select the character set to exclude.
        - return_dict (bool): If True, returns the dicitonary containing all possible exluce types.

        #### Returns:
        - str: The selected character set based on the key to be excluded from the generated passkey.

        #### Possible values for __key:
        - 'punct': Excludes punctuation characters.
        - 'ascii': Excludes ASCII letters (both uppercase and lowercase).
        - 'ascii_lower': Excludes lowercase ASCII letters.
        - 'ascii_upper': Excludes uppercase ASCII letters.
        - 'ascii_punct': Excludes both ASCII letters and punctuation characters.
        - 'ascii_lower_punct': Excludes both lowercase ASCII letters and punctuation characters.
        - 'ascii_upper_punct': Excludes both uppercase ASCII letters and punctuation characters.
        - 'digits': Excludes digits (0-9).
        - 'digits_ascii': Excludes both digits and ASCII letters.
        - 'digits_punct': Excludes both digits and punctuation characters.
        - 'digits_ascii_lower': Excludes both digits and lowercase ASCII letters.
        - 'digits_ascii_upper': Excludes both digits and uppercase ASCII letters.
        - 'digits_ascii_lower_punct': Excludes digits, lowercase ASCII letters, and punctuation characters.
        - 'digits_ascii_upper_punct': Excludes digits, uppercase ASCII letters, and punctuation characters.
        - 'hexdigits': Excludes hexadecimal digits (0-9, a-f, A-F).
        - 'hexdigits_punct': Excludes hexadecimal digits and punctuation characters.
        - 'hexdigits_ascii': Excludes hexadecimal digits and ASCII letters.
        - 'hexdigits_ascii_lower': Excludes hexadecimal digits and lowercase ASCII letters.
        - 'hexdigits_ascii_upper': Excludes hexadecimal digits and uppercase ASCII letters.
        - 'hexdigits_ascii_punct': Excludes hexadecimal digits, ASCII letters, and punctuation characters.
        - 'hexdigits_ascii_lower_punct': Excludes hexadecimal digits, lowercase ASCII letters, and punctuation characters.
        - 'hexdigits_ascii_upper_punct': Excludes hexadecimal digits, uppercase ASCII letters, and punctuation characters.
        """
        all_chars = {
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
            "hexdigits_ascii_lower_punct": hexdigits + ascii_lowercase + punctuation,
            "hexdigits_ascii_upper_punct": hexdigits + ascii_uppercase + punctuation,
        }
        if return_dict:
            return all_chars
        return all_chars.get(__key)

    @classmethod
    def _sig_larger(cls, *args) -> NamedTuple:
        """
        Calculate the significant difference between two numerical values.

        - Special Note:
            - The 'status' field indicates whether the absolute difference between the provided values
            is within the threshold (1e5). If 'status' is False, the 'threshold' field will be the maximum
            of the provided values and the threshold.
        """

        valid_args = all((map(partial(cls._validate_object, arg="Key Length"), args)))

        if len(args) == 2 or valid_args:
            threshold = cls._MAX_TOKENS
            Sig = namedtuple("SigLarger", ("status", "threshold"))
            abs_diff = abs(operator.sub(*args))
            status: bool = operator.le(*map(math.log1p, (abs_diff, threshold)))
            return Sig(status, max(max(args), threshold))
        raise CipherException(
            "Excessive arguments provided; requires precisely two numerical values, such as integers or floats."
        )

    @classmethod
    def _generate_key(
        cls,
        *,
        key_length: int = 32,
        exclude: str = "",
        include_all_chars: bool = False,
        bypass_keylength: bool = False,
        repeat: int = None,
        urlsafe_encoding=False,
    ) -> Union[str, bytes]:
        if all((exclude, include_all_chars)):
            raise CipherException(
                "Cannot specify both 'exclude' and 'include_all_chars' parameters."
            )

        if repeat:
            repeat_val = cls._validate_object(repeat, type_is=int, arg="repeat")
        else:
            repeat_val = cls._MAX_TOKENS

        cls._validate_object(key_length, type_is=int, arg="Key Length")
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
                    "It is recommended to use a count of 32 <= x <= 512, considering the specified 'key_length'. \n"
                    f"\nMax Capacity: {cls._MAX_CAPACITY:_}"
                    f"\nCharacter Repeat Count: {repeat_val:_}"
                )
            elif bypass_keylength:
                CipherException(
                    "The specified count(s) indicate a potentially high magnitude. "
                    "Please take into account the substantial computational resources that may be required to process such large values.",
                    log_method=logger.info,
                )

        threshold = cls._sig_larger(key_length, int(repeat_val))
        if not threshold.status:
            cls._MAX_TOKENS = threshold.threshold
            CipherException(
                "The specified values for 'key_length' or 'iterations' (repeat) exceeds the number of characters that can be cycled during repetition. "
                f"Higher values for 'max_tokens' count is recommended for better results ('max_tokens' count is now {cls._MAX_TOKENS}).",
                log_method=logger.warning,
            )

        slicer = lambda *args: "".join(islice(*args, cls._MAX_TOKENS))
        all_chars = slicer(cycle(cls._ALL_CHARS))
        filtered_chars = cls._filter_chars(all_chars, exclude=punctuation)

        if include_all_chars:
            filtered_chars = all_chars

        if exclude:
            exclude = cls._validate_object(exclude, type_is=str, arg="exclude_chars")
            filter_char = partial(cls._filter_chars, all_chars)
            exclude_type = cls._exclude_type(exclude)
            filtered_chars = (
                filter_char(exclude=exclude)
                if not exclude_type
                else filter_char(exclude=exclude_type)
            )

        passkey = secrets.SystemRandom().sample(
            population=filtered_chars, k=min(key_length, len(filtered_chars))
        )
        crypto_key = "".join(passkey)
        if urlsafe_encoding:
            crypto_key = cls._base64_key(crypto_key.encode())
        return crypto_key

    @classmethod
    def _fernet_mapper(cls, keys) -> Iterable[Fernet]:
        return cls._EXECUTOR.map(Fernet, keys)


class _BasePower:
    """
    ### Base class providing common attributes for power-related configurations in the CipherEngine.

    #### Attributes:
        - `_MHZ`: str: Suffix for MegaHertz.
        - `_GHZ`: str: Suffix for GigaHertz.
        - `_POWER`: None: Placeholder for power-related information.
        - `_SPEED`: None: Placeholder for speed-related information.
        - `_MIN_CORES`: int: Minimum number of CPU cores (default: 2).
        - `_MAX_CORES`: int: Maximum number of CPU cores (default: 64).
        - `_MIN_POWER`: int: Minimum capacity for cryptographic operations (default: 10,000).
        - `_MAX_POWER`: int: Maximum capacity for cryptographic operations (default: 100,000,000).
    """

    _MHZ = "MHz"
    _GHZ = "GHz"
    _POWER = None
    _SPEED = None
    _MIN_CORES = 2
    _MAX_CORES = 64
    _MIN_POWER = int(1e5)
    _MAX_POWER = _BaseCryptoEngine._MAX_CAPACITY

    def __init__(self) -> None:
        pass

    @property
    def clock_speed(self) -> NamedTuple:
        if self._SPEED is None:
            self._SPEED = self._get_clock_speed()
        return self._SPEED

    @property
    def cpu_power(self) -> Union[int, dict[int, int]]:
        if self._POWER is None:
            self._POWER = self._get_cpu_power()
        return self._POWER

    def calculate_cpu(self, **kwargs) -> Union[int, dict[int, int]]:
        return self._get_cpu_power(**kwargs)

    def _get_cpu_chart(self) -> dict[int, int]:
        """CPU _Power Chart"""
        return self._get_cpu_power(return_dict=True)

    @classmethod
    def _get_clock_speed(cls) -> NamedTuple:
        Speed = namedtuple("ClockSpeed", ("speed", "unit"))
        frequencies = psutil.cpu_freq(percpu=False)
        if frequencies:
            mega, giga = cls._MHZ, cls._GHZ
            clock_speed = frequencies.max / 1000
            unit = giga if clock_speed >= 1 else mega
            return Speed(clock_speed, unit)
        raise CipherException(
            "Unable to retrieve CPU frequency information to determine systems clock speed."
        )

    def _get_cpu_power(
        self,
        min_power: bool = False,
        max_power: bool = False,
        return_dict: bool = False,
    ) -> Union[int, dict[int, int]]:
        if all((min_power, max_power)):
            max_power = False

        base_power_range = np.logspace(
            np.log10(self.min_cores),
            np.log10(self._MIN_POWER),
            self._MIN_POWER,
            self._MAX_POWER,
        ).astype("float64")
        base_power = base_power_range[self.max_cores + 1] * self._MIN_POWER
        cpu_counts = np.arange(self.min_cores, self.max_cores // 2)
        cpu_powers = np.multiply(base_power, cpu_counts, order="C", subok=True).astype(
            "int64"
        )
        cpu_chart = OrderedDict(zip(cpu_counts, cpu_powers))

        if return_dict:
            return cpu_chart

        try:
            total_power = cpu_chart[
                self.min_cores + min((self.min_cores % 10, self.max_cores % 10))
            ]
        except KeyError:
            total_power = next(iter(cpu_chart.values()))

        first_or_last = lambda _x: next(iter(_x[slice(-1, None, None)]))

        if any(
            (
                min_power,
                total_power >= self._MAX_POWER,
                self.clock_speed.unit == self._MHZ,
            )
        ):
            total_power = first_or_last(cpu_chart.popitem(last=False))

        if max_power and (
            self.clock_speed.unit == self._GHZ and not total_power >= self._MAX_POWER
        ):
            total_power = first_or_last(cpu_chart.popitem(last=True))
            CipherException(
                "CAUTION: The 'max_power' parameter is designed to determine the maximum number "
                "of iterations used in the algorithm's encryption/decryption process, with consideration "
                "for high-end computational power, specifically GigaHertz (GHz). Please ensure your system "
                "meets the required computational prerequisites before using this option."
                f"\nIterations being used {total_power:_}"
                f"\nBase2: {math.ceil(math.log2(total_power)):_}",
                log_method=logger.warning,
            )

        return total_power

    @classmethod
    def _capacity_error(cls, __strings) -> NoReturn:
        raise CipherException(
            f"The specified counts surpasses the computational capacity required for {cls.__name__!r}. "
            f"It is recommended to use a count of {int(1e3):_} <= x <= {int(1e6):_}, considering the specified 'key_length'. "
            f"{__strings}"
        )

    @property
    def default_cpu_count(self):
        return os.cpu_count() or 1

    @property
    def max_cores(self):
        if self.default_cpu_count > self._MAX_CORES:
            self._MAX_CORES = self.default_cpu_count
        return self._MAX_CORES

    @property
    def min_cores(self):
        if self.default_cpu_count < self._MIN_CORES:
            self._MIN_CORES = self.default_cpu_count
        return self._MIN_CORES


@dataclass(kw_only=True)
class _BaseEngine(_BaseCryptoEngine, _BasePower):
    """
    Base class for the CipherEngine hierarchy, providing common attributes and functionality for encryption.
    """

    # XXX Shared methods and attributes across all engines.
    overwrite_file: Optional[bool] = field(repr=False, default=False)
    identifiers: Optional[tuple[str, str]] = field(repr=False, default=None)
    verbose: bool = field(repr=False, default=False)

    _AES: str = "aes"
    _DEC: str = "dec"
    _CFG: str = "cfg"
    _JSON: str = "json"
    _PRE_ENC: str = "encrypted"
    _PRE_DEC: str = "decrypted"

    def _print_headers(engine="", method="") -> str:
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                repr_name = (
                    lambda status: "{} {} Tool {}".format(engine, method, status)
                    .upper()
                    .center(_BaseEngine._terminal_size(), "=")
                )
                CEinfo = partial(CipherException, log_method=logger.info)
                CEinfo(repr_name("activated"))
                CEinfo(
                    f"{engine!r} {method} algorithm has begun. Gathering prerequisites..."
                )
                func_method = func(*args, **kwargs)
                CEinfo(repr_name("de-activated"))
                CEinfo(f"{engine!r} {method} algorithm has ended.")
                return func_method

            return wrapper

        return decorator

    def _get_serializer(self) -> str:
        if not self.serializer:
            return self._CFG
        return self._validate_object(self.serializer, type_is=str, arg="Serializer")

    @classmethod
    def _new_parser(cls) -> configparser.ConfigParser:
        return configparser.ConfigParser()

    @classmethod
    def _str2any(cls, key=None) -> Union[bytes, str]:
        if isinstance(key, str):
            key = ast.literal_eval(key)
        return key

    @classmethod
    def _log2_conversion(cls, value) -> int:
        return math.ceil(math.log2(value))

    @classmethod
    def _failed_hash(
        cls, org_hash: bytes, second_hash: bytes, file_hashes=None
    ) -> None:
        file_hash_str = ""
        if file_hashes:
            org_file_hash, decr_file_hash = file_hashes
            file_hash_str = (
                f"\nOriginal File Hash: {org_file_hash}"
                f"\nDecrypted File Hash: {decr_file_hash}"
            )
        raise CipherException(
            "The discrepancy in hashed values points to a critical integrity issue, suggesting potential data loss. "
            "Immediate data investigation and remedial action are strongly advised. "
            f"\nOriginal Hash: {org_hash}"
            f"\nDecrypted Hash: {second_hash}"
            f"{file_hash_str}"
        )

    @staticmethod
    def _template_parameters() -> set:
        """All key sections for configuration file."""
        return {
            "aes_iv",
            "aes_passkey",
            "decipher_keys",
            "encrypted_file",
            "encrypted_text",
            "hash_value",
            "id1",
            "id2",
            "iterations",
            "original_file",
            "original_text",
            "passkey",
            "r_and_p",
            "salt_bytes_size",
            "salt_values",
        }

    @classmethod
    def _check_headers(
        cls, __data: str, headers, msg="", method=all, positive=False
    ) -> None:
        """Checks whether specified data contains the correct encryption identifiers."""
        start, end = headers
        try:
            result = method((__data.startswith(start), __data.endswith(end)))
        except TypeError:
            result = method(
                (__data.startswith(start.decode()), __data.endswith(end.decode()))
            )
        if positive and not result:
            raise CipherException(msg)
        elif not positive and result:
            raise CipherException(msg)
        return True

    @classmethod
    def _base_engines(cls, engine: str) -> str:
        engines = cls._validate_object(engine, type_is=str, arg="Class Engine")
        splitter = lambda s: str(s).strip("'<>").split(".")[-1]
        return next(c for c in inspect.getmro(cls) if splitter(c) == splitter(engines))

    @staticmethod
    def _new_template(**kwargs) -> dict:
        """
        #### \
        This method creates a dynamic template incorporating encryption parameters and security details \
        suitable for writing encrypted data to a file. \
        The generated template can later be employed in the decryption process.
        """

        kpopper = lambda key: kwargs.pop(key, None)
        file_hash = kpopper(file_hash_str := "file_hash_value")
        kwargs = {file_hash_str: file_hash, **kwargs} if file_hash else kwargs

        # XXX CIPHER_INFO Section
        org_str = "original_{}".format("file" if "encrypted_file" in kwargs else "text")
        org_data = kpopper(org_str)
        encr_str = "encrypted_{}".format(
            "file" if "encrypted_file" in kwargs else "text"
        )
        encr_data = kpopper(encr_str)

        # XXX AES Encryption Section
        aes_iv = kpopper(aes_iv_str := "aes_iv")
        aes_passkey = kpopper(aes_pass_str := "aes_passkey")

        # XXX SECURITY_PARAMS Section
        security_params = (
            {**kwargs}
            if not aes_iv
            else {**kwargs, aes_iv_str: aes_iv, aes_pass_str: aes_passkey}
        )
        return {
            "CIPHER_INFO": {org_str: org_data, encr_str: encr_data},
            "SECURITY_PARAMS": security_params,
        }

    @classmethod
    def _key_deriver(cls, *args, num_keys=2, rp=(8, 1)) -> Iterator:
        """Salt, Iterations, Keys"""
        try:
            salt, iterations, key = args
        except ValueError:
            salt, iterations, key = args[0]

        kderiver = cls._create_subclass("KeyDeriver", field_names=("key", "salt"))
        if isinstance(key, str):
            key = key.encode()
        scrypt_deciphers = scrypt(
            key,
            salt,
            key_len=cls._MAX_KEYLENGTH,
            N=iterations,
            r=rp[0],
            p=rp[1],
            num_keys=num_keys,
        )
        deciphers = cls._EXECUTOR.map(
            lambda d: kderiver(cls._base64_key(d), salt.hex()), scrypt_deciphers
        )
        return deciphers

    @staticmethod
    def _format_file(__file: P) -> str:
        time_now = datetime.now()
        formatted_time = time_now.strftime("%Y-%m-%dT%I-%M-%S%p-")
        return (__file.parent / formatted_time).as_posix() + (f"backup-{__file.name}")

    @staticmethod
    def _read_file(__file: P, mode="rb") -> Union[bytes, str]:
        with open(__file, mode=mode) as _file:
            _text = _file.read()
        return _text

    @staticmethod
    def none_generator(__data, default=None) -> list:
        return [default] * len(__data)

    @classmethod
    def _create_subclass(
        cls,
        typename: str = "FieldTuple",
        /,
        field_names: Iterable = None,
        *,
        module: str = None,
        defaults: Iterable = None,
        values: Iterable = None,
        field_doc: str = "",
    ) -> NamedTuple:
        default_vals = defaults or cls.none_generator(field_names)

        field_docs = field_doc or "Field documentation not provided."
        module_name = module or typename
        new_tuple = namedtuple(
            typename=typename,
            field_names=field_names,
            defaults=default_vals,
            module=module_name,
        )
        setattr(new_tuple, "__doc__", field_docs)
        if values:
            return new_tuple(*values)
        return new_tuple

    @classmethod
    def _validate_file(cls, __file: P) -> Path:
        try:
            _file = cls._validate_object(
                __file, type_is=Path, arg="Specified File Path"
            )
        except TypeError as t_error:
            raise CipherException(t_error)

        if not _file:
            raise CipherException(f"File arugment must not be empty: {_file!r}")
        elif not _file.exists():
            raise CipherException(
                f"File does not exist: {_file!r}. Please check system files."
            )
        elif all((not _file.is_file(), not _file.is_absolute())):
            raise CipherException(
                f"Invalid path type: {_file!r}. Path must be a file type."
            )
        elif _file.is_dir():
            raise CipherException(
                f"File is a directory: {_file!r}. Argument must be a valid file."
            )
        return _file

    @classmethod
    def convert2strings(cls, __data) -> dict:
        return {
            k: str(v) if not isinstance(v, dict) else cls.convert2strings(v)
            for k, v in __data.items()
        }

    @staticmethod
    def _terminal_size() -> int:
        return shutil.get_terminal_size().columns

    @classmethod
    def _replace_file(cls, fp, overwrite=False) -> Union[Path, None]:
        new_path = fp.parent
        if overwrite:
            new_file = new_path / fp.stem
            CipherException(f"Overwriting {fp!r}...", log_method=logger.info)
            os.remove(fp)
        else:
            if fp.is_file():
                prefix = cls._PRE_ENC
                _name = fp.stem.removeprefix(prefix)
                if re.search(r"\.", _name):
                    _name = fp.stem.split(".")[0]
                new_file = fp.parent / f"{prefix}_{_name}"
                return new_file

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

    @classmethod
    def _parse_config(
        cls, cfg: P, *, section: str = "SECURITY_PARAMS", section_key: str
    ) -> str:
        cfg_path = cls._validate_object(cfg, type_is=Path, arg="Configuration File")
        file_suffix = cfg_path.suffix.lstrip(".")
        try:
            if file_suffix == cls._JSON:
                cparser = json.load(open(cfg_path))
            else:
                cparser = cls._new_parser()
                cparser.read(cfg_path)
            sec_val = cparser[section].get(section_key)
        except configparser.NoSectionError:
            raise CipherException(
                f"Confgiuration file does not contain section {section!r}"
            )
        except configparser.NoOptionError:
            raise CipherException(
                f"{section_key.capitalize()!r} was not found in {section!r} section."
                f"\nIt is imperative that the values stored in the passkey configuration file generated by {cls.__name__.upper()} encryption algorithm tool is saved and not altered in anyway. "
                "Failure to do so may alter the decryption process, potentially corrupting the files data."
            )
        except configparser.Error:
            raise configparser.Error(
                f"An unexpected error occurred while attempting to read the configuration file {cfg.name}. "
                f"The decryption algorithm is designed to work with its original values. "
                "Please note that if the passphrase contains special characters, it may result in decryption issues."
            )
        return sec_val

    @classmethod
    def _get_identifiers(cls, headers: Iterable[str]) -> tuple[bytes, bytes]:
        if (
            not headers
            or headers == ("", "")
            or not (*map(cls._char_checker, headers),)
        ):
            base_identifier = "-----{} CIPHERENGINE ENCRYPTED KEY-----"
            identifiers = (
                base_identifier.format("BEGIN"),
                base_identifier.format("END"),
            )
        elif isinstance(headers, Iterable):
            headers = cls._validate_object(
                headers, type_is=Iterable, arg="Encryption Identifier"
            )
            (*map(partial(cls._char_checker, raise_exec=True), headers),)
            identifiers = headers
        else:
            raise CipherException(
                f"The provided identifiers are deemed invalid and unsuitable for encryption purposes."
            )
        return tuple(id_.encode() for id_ in identifiers)

    @classmethod
    def _tuple2set(cls, ctuple) -> set:
        return set(ctuple._asdict())

    @property
    def _identifiers(self) -> Iterable[str]:
        headers = "" if not hasattr(self, "identifiers") else self.identifiers
        return self._get_identifiers(headers)

    @classmethod
    def _validate_ciphertuple(
        cls, ctuple: NamedTuple, external_params=None
    ) -> NamedTuple:
        all_parameters = cls._template_parameters()
        # ** isinstance(__obj, CipherTuple)?
        if hasattr(ctuple, "_fields") and all(
            (
                isinstance(ctuple, tuple),
                isinstance(ctuple._fields, tuple),
                hasattr(ctuple, "__module__"),
                ctuple.__module__
                in ("QCipherTuple", "CipherTuple", "QDecipherTuple", "DecipherTuple"),
            )
        ):
            if external_params:
                ctuple_paramters = external_params
            else:
                ctuple_set = cls._tuple2set(ctuple)
                ctuple_paramters = all_parameters & ctuple_set
            try:
                for param in ctuple_paramters:
                    param_attr = getattr(ctuple, param)
                    str_attr = cls._validate_object(
                        param_attr, type_is=str, arg="CipherTuple"
                    )
                    #! Ensure attribute is not null.
                    if any((not str_attr, not len(str_attr) >= 1)):
                        raise CipherException(
                            f">>{str_attr} is not a valid attribute value. ",
                            ">>Ensure that all predefined configuration CipherTuples have non-null values.",
                        )
            except AttributeError as attr_error:
                raise CipherException(
                    f">>Validation Failed: The following attribute is not predefined. {param}. "
                    f">>Ensure that the specified configuration {NamedTuple.__name__!r} is generated from one of the {CipherEngine.__name__!r} encryption processes. "
                    f">>ERROR: {attr_error}"
                )

        else:
            raise CipherException(
                "Invalid NamedTuple Structure:\n"
                f"{ctuple!r} must be of type {NamedTuple.__name__!r}"
            )

        return ctuple

    @classmethod
    def _create_backup(cls, __file: P) -> None:
        CEinfo = partial(CipherException, log_method=logger.info)
        backup_path = __file.parent / f"backup/{__file.name}"
        formatted_bkp = cls._format_file(backup_path)
        if not backup_path.parent.is_dir():
            CEinfo(
                "No backup folder detected. "
                f"Creating a backup folder named {backup_path.parent!r} to store original files securely."
            )
            backup_path.parent.mkdir()

        if not backup_path.is_file():
            CEinfo(
                f"Backing up {backup_path.name} to the newly-created backup folder.",
            )
            shutil.copy2(__file, formatted_bkp)

    @classmethod
    def _write2file(
        cls,
        __file: P,
        *,
        suffix: bool = "cfg",
        data: AnyStr = "",
        mode: str = "w",
        parser: configparser = None,
        reason: str = "",
    ) -> None:
        new_file = Path(__file).with_suffix(f".{suffix}")
        with open(new_file, mode=mode) as fp:
            if parser:
                parser.write(fp)
            else:
                fp.write(data)
            p_string = partial(
                "{file!r} has successfully been {reason} to {path!r}".format,
                file=fp.name,
                path=new_file.absolute(),
            )
            CipherException(
                p_string(reason=reason or "written"), log_method=logger.info
            )
        return

    @classmethod
    def _compiler(
        cls, __defaults, __k, escape_default=True, escape_k=True, search=True
    ) -> re.Match:
        valid_instances = (int, str, bool, bytes, Iterable)
        if any(
            (not __k, not isinstance(__k, valid_instances), hasattr(__k, "__str__"))
        ):
            esc_k = str(__k)
        else:
            esc_k = cls._validate_object(__k, type_is=str, arg=__k)

        defaults = map(re.escape, map(str, __defaults))
        flag = "|" if escape_default else ""
        pattern = f"{flag}".join(defaults)
        if escape_k:
            esc_k = "|".join(map(re.escape, __k))

        compiler = re.compile(pattern, re.IGNORECASE)
        if not search:
            compiled = compiler.match(esc_k)
        else:
            compiled = compiler.search(esc_k)
        return compiled


@dataclass(kw_only=True)
class CipherEngine(_BaseEngine):
    """
    `CipherEngine` class for encrypting files and text data using symmetric key `MultiFernet` cryptography.
    """

    __slots__ = (
        "__weakrefs__",
        "_text",
        "_file",
        "_file_name",
        "_export_path",
        "_serializer",
        "_iterations",
        "_passkey",
        "_original_pass",
        "_aes_passkey",
        "_original_aes",
    )

    file: Optional[P] = field(repr=False, default=None)
    file_name: Optional[str] = field(repr=False, default=None)
    text: Optional[P] = field(repr=False, default=None)
    passkey: Optional[Union[str, int]] = field(repr=False, default=None)
    key_length: Optional[int] = field(repr=True, default=_BaseEngine._MAX_KEYLENGTH)
    iterations: Optional[int] = field(repr=True, default=None)
    min_power: Optional[bool] = field(repr=False, default=False)
    max_power: Optional[bool] = field(repr=False, default=False)
    gui_passphrase: bool = field(repr=False, default=False)
    bypass_keylength: bool = field(repr=False, default=False)
    serializer: Optional[str] = field(repr=True, default=None)
    backup_file: Optional[bool] = field(repr=False, default=True)
    export_passkey: Optional[bool] = field(repr=False, default=True)
    export_path: Optional[P] = field(repr=False, default=None)
    special_keys: Optional[bool] = field(repr=False, default=None)
    advanced_encryption: Optional[bool] = field(repr=False, default=False)

    def __post_init__(self):
        logger.write_log = False if self.verbose else True

        self._file_name = self._validate_object(
            self.file_name, type_is=Path, arg="File Name"
        )
        self._export_path = self._validate_object(
            self.export_path, type_is=Path, arg="Export Path"
        )
        self._serializer = self._get_serializer()
        self._iterations = self._calculate_iterations()
        self._file = None if not self.file else self._validate_file(self.file)
        self._text = self._validate_object(self.text, type_is=str, arg="Text")
        if self.gui_passphrase:
            self.gui_passphrase = False
            self._original_pass, self._passkey = self._validate_passkey(
                self._gui_passphrase()
            )
        else:
            self._original_pass, self._passkey = self._validate_passkey(self.passkey)
        self._original_aes, self._aes_passkey = self._validate_passkey(
            self.aes_passkey, aes_pass=True
        )
        if self._original_pass == self._original_aes:
            CipherException(
                "It is not recommended to employ identical passkeys for both scrypt and AES cryptographic processes.",
                log_method=logger.warning,
            )

    def _calculate_iterations(self) -> int:
        if self.iterations:
            iter_count = self._validate_object(
                self.iterations, type_is=int, arg="Iterations"
            )
            if iter_count >= self._MAX_CAPACITY:
                return self._capacity_error(
                    f"\nSpecified value: {iter_count}\n"
                    f"Max Iterations value: {self._MAX_CAPACITY}"
                )
            return iter_count
        args = (self.min_power, self.max_power)
        if any(args):
            power_info = self._create_subclass(
                "PStats",
                ("min", "max"),
                values=args,
                module="PowerInfo",
                field_doc="Minimum and maximum values for number of iterations.",
            )

            return self.calculate_cpu(
                min_power=power_info.min, max_power=power_info.max
            )
        return self.cpu_power

    def _gui_passphrase(self):
        root = tk.Tk()
        root.withdraw()
        gui_pass = simpledialog.askstring(
            "GUI-Passphrase", "Enter a secure passkey:", show="*"
        )
        root.destroy()
        return gui_pass

    def _get_key_length(self):
        return [32, self.key_length][self.key_length in self._AES_KSIZES]

    def _validate_passkey(self, passphrase=None, aes_pass=False) -> str:
        def validator(kpass):
            self._char_checker(kpass, raise_exec=True)
            if not self.bypass_keylength and 0 < len(kpass) < self._MAX_KEYLENGTH:
                kpass = self._generate_key(key_length=32)
            return kpass

        pass_method = sum(
            1 for arg in (self.gui_passphrase, self.special_keys, passphrase) if arg
        )
        original_key = special_keys = None
        if not pass_method:
            special_keys = True
        elif pass_method > 1:
            raise CipherException(
                "Can only specify one type of passkey generation method."
            )
        key_generator = partial(
            self._generate_key,
            exclude=self.exclude_chars,
            include_all_chars=self.include_all_chars,
            bypass_keylength=self.bypass_keylength,
        )
        if aes_pass:
            if not passphrase:
                original_key = key_generator(key_length=self._get_key_length())
                passkey = original_key.encode()
            else:
                original_key = validator(passphrase)
                passkey = original_key.encode()
                if len(original_key) not in self._AES_KSIZES:
                    CipherException(
                        f"The AES passkey must have a fixed length of any of the following: {self._AES_KSIZES}. "
                        f"The provided passkey is {len(passkey)!r} bytes long. "
                        "To ensure compatibility, it will be hashed using SHA-512, and a 32-byte key will be derived.",
                        log_method=logger.error,
                    )
                    passkey = self._calc_str_hash(passkey, encode=False)[:32].encode()

        else:
            if passphrase:
                passkey = original_key = validator(passphrase)
            elif self.special_keys or special_keys:
                original_key = key_generator(key_length=self.key_length)
                passkey = self._base64_key(original_key.encode())
            else:
                # XXX Overrides traditional os.urandom for secrets.token_bytes
                passkey = self._base64_key(self._gen_random(self.salt_size))
        return original_key, passkey

    def _export_passkey(self, *, parser, passkey_file, data) -> None:
        passkey_suffix = self._serializer
        write_func = partial(self._write2file, passkey_file, reason="exported")
        write2file = partial(write_func, suffix=passkey_suffix, parser=parser)

        def json_serializer():
            org_data = self.convert2strings(data)
            new_data = json.dumps(org_data, indent=2, ensure_ascii=False)
            passkey_suffix = self._JSON
            write2file = partial(write_func, suffix=passkey_suffix, data=new_data)
            return write2file

        CipherException(
            "Writing dependencies onto passkey configuration file...",
            log_method=logger.info,
        )

        if passkey_suffix == "json":
            write2file = json_serializer()
        else:
            try:
                parser.update(**self.convert2strings(data))
            except ValueError:
                CipherException(
                    "Usage of special characters in configurations (ConfigParser module) may not be optimal and could potentially result in errors. "
                    "As a result, the system will proceed to serialize the data in JSON (.json) format to guarantee compatibility with any special characters.",
                    log_method=logger.error,
                )
                write2file = json_serializer()

        if self.export_passkey:
            write2file()

    def _base_error(self, __data=None) -> str:
        if not __data:
            __data = "the data"
        return (
            f"{self.__class__.__name__.upper()} encrypter identifications detected signaling that {__data!r} is already encrypted. "
            "\nRe-encrypting it poses a significant risk of resulting in inaccurate decryption, potentially leading to irreversible data corruption. "
            "\nIt is crucial to decrypt the data first before attempting any further encryption."
            "\n\nStrictly limit the encryption process to once per object for each subsequent decryption to safeguard against catastrophic data loss."
        )

    @classmethod
    def _ciphertuple(cls, *args, type_file=False, class_only=False) -> NamedTuple:
        """
        ('decipher_key', 'encrypted_text/file',
        'fernet_encrypted_text', 'fernets', 'hash_value',
        'id1', 'id2', 'iterations', 'original_text/file',
        'passkey', 'private_key', 'public_key',
        'rsa_bits_size', 'rsa_encrypted_text', 'rsa_iterations',
        'rsa_passphrase', 'salt_byte_size', 'salt_values')
        """
        if not class_only:
            parameters = cls._template_parameters()
            specific_params = (
                k
                for k in parameters
                if (type_file and not k.endswith("text"))
                or (not type_file and not k.endswith("file"))
            )
            ordered_params = sorted(specific_params)
            values = cls.none_generator(ordered_params) if not args else args
        else:
            ordered_params, values = args
        return cls._create_subclass(
            "CipherTuple",
            field_names=ordered_params,
            values=values,
            field_doc="Primary NamedTuple \
                                            for storing encryption details.",
        )

    def _aes_encrypt(self, encoded_text):
        cipher = AES.new(self._aes_passkey, mode=AES.MODE_CBC, iv=self.aes_bits)
        padded_text = pad(encoded_text, self._AES_BSIZE)
        cipher_text = cipher.encrypt(padded_text)
        cipherkey = self._create_subclass(
            "CipherKey",
            field_names=("ciphertext", "IV"),
            field_doc="Tuple containing AES encryption dependecies.",
        )
        return cipherkey(cipher_text, cipher.iv.hex())

    def _bkp_overwrite_file(self, original_file, text_only=False):
        if not original_file:
            raise CipherException(
                f"Specified file cannot be null for encryption. Error on ({original_file!r})"
            )
        def_suffix = self._AES
        file_hash_val = self._calc_file_hash(original_file)
        plain_text = self._read_file(original_file, mode="r")
        self._check_headers(
            plain_text,
            self._identifiers,
            msg=self._base_error(original_file),
            method=any,
        )
        if text_only:
            return plain_text
        if not self.backup_file or (self.overwrite_file and not self.backup_file):
            CipherException(
                "Disabling the 'backup_file' parameter poses a significant risk of potential data loss. "
                "It is strongly advised to consistently back up your data before initiating any encryption processes to mitigate potential data loss scenarios.",
                log_method=logger.warning,
            )

        if self.backup_file:
            self._create_backup(original_file)

        if self.overwrite_file:
            def_suffix = original_file.suffix.lstrip(".")
            encr_file = original_file.parent / original_file.stem
            CipherException(f"Overwriting {original_file!r}...", log_method=logger.info)
            os.remove(original_file)
        else:
            if original_file.is_file():
                prefix = self._PRE_ENC
                fp_name = original_file.stem.removeprefix(prefix)
                if re.search(r"\.", fp_name):
                    fp_name = original_file.stem.split(".")[0]
                encr_file = original_file.parent / f"{prefix}_{fp_name}"
        return plain_text, file_hash_val, encr_file, def_suffix

    def encrypt_file(self) -> NamedTuple:
        original_file = self._file
        bkp_overwrite = partial(self._bkp_overwrite_file, self._file)
        plain_text = bkp_overwrite(text_only=True)
        ctuple = CipherEngine(
            text=plain_text,
            export_passkey=False,
            **{
                k: v
                for k, v in self.__dict__.items()
                if all((k[0] != "_", k != "text", k != "export_passkey"))
            },
        ).encrypt_text()
        plain_text, file_hash_val, encr_file, def_suffix = bkp_overwrite()
        new_data = OrderedDict({"file_hash_value": file_hash_val})
        for k, v in ctuple._asdict().items():
            if k == "original_text":
                k = "original_file"
                v = original_file
            elif k == "encrypted_text":
                k = "encrypted_file"
                v = encr_file.with_suffix(f".{def_suffix}")
            new_data[k] = v

        encryption_data = (
            ctuple.encrypted_text.encode()
            if hasattr(ctuple.encrypted_text, "encode")
            else ctuple.encrypted_text
        )
        self._write2file(
            encr_file,
            suffix=def_suffix,
            mode="wb",
            data=encryption_data,
            reason="exported",
        )
        passkey_name = self._file_name or Path(f"{encr_file.stem}_passkey")
        passkey_file = original_file.parent / passkey_name
        encr_data = self._new_template(**new_data)

        if self.export_passkey:
            self._export_passkey(
                parser=self._new_parser(), passkey_file=passkey_file, data=encr_data
            )
        return self._update_ctuple(encr_data)

    def encrypt_text(self) -> NamedTuple:
        if not self._text:
            raise CipherException(
                f"Specified text cannot be null for encryption. Error on ({self._text!r})"
            )

        cpu_iterations = 2 ** self._log2_conversion(self._iterations)
        hash_val = self._calc_str_hash(self._text)
        self._check_headers(
            self._text, self._identifiers, msg=self._base_error(), method=any
        )
        passkey = (
            self._passkey
            if not hasattr(self._passkey, "encode")
            else self._passkey.encode()
        )
        start_key, end_key = self._identifiers
        decipher_keys = tee(
            tuple(
                self._EXECUTOR.map(
                    lambda s: self._key_deriver(
                        s,
                        cpu_iterations,
                        passkey,
                        num_keys=self.num_of_salts,
                        rp=(self.block_size, self.p),
                    ),
                    self.gen_salts,
                )
            )[0],
            3,
        )
        fernets = self._fernet_mapper((k.key for k in decipher_keys[0]))
        mfernet = self._get_fernet(fernets)
        mfernet_encryption = mfernet.encrypt(self._text.encode())
        hex_encoder = lambda p: p.encode().hex() if isinstance(p, str) else p.hex()
        aes_iv = aeskey_data = None
        if self.advanced_encryption:
            advanced_encryption = self._aes_encrypt(self._text.encode())
            mfernet_encryption = mfernet.encrypt(advanced_encryption.ciphertext)
            aes_iv = advanced_encryption.IV
            aeskey_data = (self._original_aes, hex_encoder(self._aes_passkey))
        encrypted_text = start_key + mfernet_encryption + end_key
        ciphertuple = self._ciphertuple(
            aes_iv,
            aeskey_data,
            tuple(k.key.decode() for k in decipher_keys[1]),
            encrypted_text.decode(),
            hash_val,
            start_key.decode(),
            end_key.decode(),
            cpu_iterations,
            self._text,
            (self._original_pass, hex_encoder(self._passkey)),
            (self.block_size, self.p),
            self.salt_bytes_size,
            tuple(s.salt for s in decipher_keys[2]),
        )
        ctuple_data = self._new_template(**ciphertuple._asdict())
        if self.export_passkey:
            fp = self._file_name or "ciphertext_passkey"
            if self.export_path:
                fp = self._export_path / fp
            self._export_passkey(
                parser=self._new_parser(), passkey_file=fp, data=ctuple_data
            )
        return self._update_ctuple(ctuple_data)

    def _update_ctuple(self, ctuple_dict: dict):
        """Returns updated CipherTuple based the encryption type used."""
        cipher_info, security_params = (
            ctuple_dict["CIPHER_INFO"],
            ctuple_dict["SECURITY_PARAMS"],
        )
        field_names = chain.from_iterable((cipher_info, security_params))
        values = chain.from_iterable((cipher_info.values(), security_params.values()))
        return self._ciphertuple(tuple(field_names), tuple(values), class_only=True)

    def quick_encrypt(self):
        get_fernet = partial(self._get_fernet, fernet_type=Fernet)
        qctuple_class = self._create_subclass(
            "QCipherTuple",
            (
                "original_file" if self._file else "original_text",
                "encrypted_file" if self._file else "encrypted_text",
                "hash_value",
                "passkey",
            ),
            field_doc="Primary NamedTuple for quick encryptions.",
        )
        org_key = self._original_pass
        fixed_size_key = self._calc_str_hash(org_key)[: self._MAX_KEYLENGTH]
        passkey = self._base64_key(fixed_size_key.encode())
        if self._text:
            text_hash = self._calc_str_hash(self._text)
            fernet = get_fernet(passkey, fernet_type=Fernet)
            encrypted_text = fernet.encrypt(self._text.encode())
            passkey_data = (org_key, passkey.decode())
            qctuple = qctuple_class(
                self._text, encrypted_text.decode(), text_hash, passkey_data
            )
        if self._file:
            def_suffix = self._AES
            plain_text, file_hash_val, encr_file, def_suffix = self._bkp_overwrite_file(
                self._file
            )
            fernet = get_fernet(passkey, fernet_type=Fernet)
            encrypted_text = fernet.encrypt(plain_text.encode())
            passkey_data = (org_key, passkey.decode())
            qctuple = qctuple_class(
                self._file,
                encr_file.with_suffix(f".{def_suffix}"),
                file_hash_val,
                passkey_data,
            )
            self._write2file(
                encr_file,
                suffix=def_suffix,
                mode="wb",
                data=encrypted_text,
                reason="exported",
            )
            passkey_name = self._file_name or Path(f"{encr_file.stem}_passkey")
            fp = self._file.parent / passkey_name

        if self.export_passkey:
            fp = self._file_name or "qcipher_passkey"
            if self.export_path:
                fp = self._export_path / fp
            qctuple_data = self._new_template(**qctuple._asdict())
            self._export_passkey(
                parser=self._new_parser(), passkey_file=fp, data=qctuple_data
            )
        return qctuple


@dataclass(kw_only=True)
class DecipherEngine(_BaseEngine):
    """
    DecipherEngine is a class designed to decrypt data encrypted through the CipherEngine.
    This class specifically operates with (configuration files | CipherTuples) generated by the CipherEngine during the encryption process.
    """

    __slots__ = (
        "__weakrefs__",
        "_passkey_file",
        "_decipher_keys",
        "_hash_value",
        "_iterations",
        "_passkey",
        "_id1",
        "_id2",
        "_r_and_p",
        "_salt_bytes_size",
        "_salt_values",
        "_aes_passkey",
        "_file_hash_value",
        "_aes_iv",
        "_encrypted_data",
        "_encrypted_text",
        "_encrypted_file",
        "_ciphertuple",
    )

    ciphertuple: Optional[NamedTuple] = field(repr=False, default=None)
    passkey_file: Optional[P] = field(repr=False, default=None)
    manual_kwgs: dict = field(repr=False, default_factory=dict)

    def __post_init__(self):
        logger.write_log = False if self.verbose else True
        
        # ** For configuration files (.cfg)
        if all((self.passkey_file, self.ciphertuple, self.manual_kwgs)):
            raise CipherException("Cannot simultaneously specify all arguments.")
        elif not any((self.passkey_file, self.ciphertuple, self.manual_kwgs)):
            raise CipherException(
                f"One of three optional keyword-only arguments are expected for {DecipherEngine.__name__!r}, "
                "but none were provided."
            )
        self._typeis_file = False
        self._aes_encrypted = False
        if self.passkey_file:
            self._passkey_file = self._validate_file(self.passkey_file)
            cparser_func = partial(self._parse_config, self._passkey_file)
            self._decipher_keys = cparser_func(section_key="decipher_keys")
            self._hash_value = cparser_func(section_key="hash_value")
            self._iterations = cparser_func(section_key="iterations")
            self._passkey = cparser_func(section_key="passkey")
            self._id1 = cparser_func(section_key="id1")
            self._id2 = cparser_func(section_key="id2")
            self._aes_iv = cparser_func(section_key="aes_iv")
            self._r_and_p = cparser_func(section_key="r_and_p")
            self._salt_bytes_size = cparser_func(section_key="salt_bytes_size")
            self._aes_passkey = cparser_func(section_key="aes_passkey")
            self._salt_values = cparser_func(section_key="salt_values")
            self._file_hash_value = cparser_func(section_key="file_hash_value")
            sec_getter = lambda sec_key: cparser_func(
                section="CIPHER_INFO", section_key=sec_key
            )
            self._encrypted_text = sec_getter(sec_key="encrypted_text")
            self._encrypted_file = sec_getter(sec_key="encrypted_file")

        # ** For CipherTuple instances.
        if self.ciphertuple:
            self.ciphertuple = self._validate_ciphertuple(self.ciphertuple)
            self._encrypted_text = (
                self.ciphertuple.encrypted_text
                if hasattr(self.ciphertuple, "encrypted_text")
                else None
            )
            self._encrypted_file = (
                self.ciphertuple.encrypted_file
                if hasattr(self.ciphertuple, "encrypted_file")
                else None
            )
            self._file_hash_value = (
                self.ciphertuple.file_hash_value
                if hasattr(self.ciphertuple, "file_hash_value")
                else None
            )
            self._hash_value = self.ciphertuple.hash_value
            self._passkey = self.ciphertuple.passkey
            # XXX Attributes for basic encryption.
            if hasattr(self.ciphertuple, "r_and_p"):
                self._r_and_p = self.ciphertuple.r_and_p
                self._iterations = self.ciphertuple.iterations
                self._decipher_keys = self.ciphertuple.decipher_keys
                self._id1 = self.ciphertuple.id1
                self._id2 = self.ciphertuple.id2
                self._salt_values = self.ciphertuple.salt_values
                self._salt_bytes_size = self.ciphertuple.salt_bytes_size
            # XXX Attributes for AES Encryption.
            if hasattr(self.ciphertuple, "aes_passkey"):
                self._aes_passkey = self.ciphertuple.aes_passkey
                self._aes_iv = self.ciphertuple.aes_iv
        if self.manual_kwgs:
            all_params = self._template_parameters()
            for k, v in self.manual_kwgs.items():
                if k in all_params:
                    setattr(self, f"_{k}", v)
                else:
                    raise CipherException(
                        f"DecipherEngine.__init__() got an unexpected keyword argument ({k!r})."
                    )

        if not self._encrypted_text and self._encrypted_file:
            self._typeis_file = True
            self._encrypted_data = self._encrypted_file
        else:
            self._encrypted_data = self._encrypted_text
        if hasattr(self, "_aes_passkey") and self._aes_passkey:
            self._aes_encrypted = True

    @classmethod
    def _get_subclass(cls, type_file=False, quick_cipher=False) -> NamedTuple:
        typename = "{}DecipherTuple".format("Q" if quick_cipher else "")
        decr_type = "decrypted_{}".format("file" if type_file else "text")
        return cls._create_subclass(typename, field_names=(decr_type, "hash_value"))

    @classmethod
    def _validate_token(cls, __mfernet, encrypted_text):
        encrypted_text = (
            encrypted_text
            if not hasattr(encrypted_text, "encode")
            else encrypted_text.encode()
        )
        try:
            decr_text = __mfernet.decrypt(encrypted_text).decode()
        except InvalidToken:
            decr_text = None
        return decr_text

    def _base_error(self) -> str:
        return (
            f"The data provided lacks the required identifiers. "
            f"\n{self.__class__.__name__.upper()}'s decryption algorithm only operates with data containing its designated identifiers. "
            f"\nEncryption algorithms identifiers:\n{self._identifiers}"
        )

    def _overwrite_file(self, decrypted_data):
        if not self._typeis_file:
            raise CipherException(
                f"Specified file cannot be null for decryption. Error on ({self._encrypted_file!r})"
            )
        encr_data = Path(self._encrypted_data)
        default_suffix = self._DEC
        if self.overwrite_file:
            default_suffix = encr_data.name.split(".")[-1]
            decrypted_file = encr_data.as_posix()
            os.remove(encr_data)
        else:
            if encr_data.is_file():
                prefix = self._PRE_DEC
                fp_name = encr_data.stem.removeprefix(prefix)
                if re.search(r"\.", fp_name):
                    fp_name = encr_data.stem.split(".")[0]
                decrypted_file = encr_data.parent / f"{prefix}_{fp_name}"
        decrypted_file = Path(decrypted_file)
        self._write2file(
            decrypted_file,
            suffix=default_suffix,
            mode="w",
            data=decrypted_data,
            reason="decrypted",
        )
        return default_suffix, decrypted_file

    def decrypt_file(self) -> NamedTuple:
        decipher_engine = DecipherEngine(
            passkey_file=self.passkey_file,
            ciphertuple=self.ciphertuple,
            manual_kwgs=self.manual_kwgs,
        ).decrypt_text()
        decrypted_data = decipher_engine.decrypted_file
        default_suffix, decrypted_file = self._overwrite_file(decrypted_data)
        decrypted_file = decrypted_file.with_suffix("." + default_suffix)
        decrypted_file_hash = self._calc_file_hash(decrypted_file)

        decrypted_data_hash = self._calc_str_hash(decrypted_data)
        all_hashes = (
            self._file_hash_value,
            decrypted_file_hash,
            self._hash_value,
            decrypted_data_hash,
        )
        hash_checked = all(h == all_hashes[0] for h in all_hashes)
        if not hash_checked:
            self._failed_hash(
                self._hash_value,
                decrypted_data_hash,
                file_hashes=(self._file_hash_value, decrypted_file_hash),
            )
        decr_tuple = self._get_subclass(type_file=True)
        return decr_tuple(decrypted_file, decrypted_data_hash)

    def decrypt_text(self) -> NamedTuple:
        def unpack_tuple(org_tuple):
            try:
                org_data = self._str2any(org_tuple)
                data = bytes.fromhex(org_data[1])
            except ValueError:
                data = org_data[1]
            return data

        obj_validator = partial(self._validate_object, type_is=str)
        encr_text = obj_validator(self._encrypted_data, arg="Encrypted Text")
        if self._typeis_file:
            encr_text = self._read_file(self._validate_object(encr_text, type_is=Path))
        encr_text = encr_text.encode() if hasattr(encr_text, "encode") else encr_text
        org_decipher_keys = self._str2any(self._decipher_keys)
        hash_value = obj_validator(self._hash_value, arg="Hash Value")
        start_key = obj_validator(self._id1, arg="Beginning Encryption Header")
        end_key = obj_validator(self._id2, arg="Ending Encryption Header")
        iterations = int(self._iterations)
        passkey = unpack_tuple(self._passkey)
        self._check_headers(
            encr_text.decode() if hasattr(encr_text, "decode") else encr_text,
            (start_key, end_key),
            msg=self._base_error(),
            method=all,
            positive=True,
        )
        fixed_salts = self._str2any(self._salt_values)
        salts = (bytes.fromhex(s) for s in fixed_salts)
        decipher_keys = (
            k.key
            for k in tuple(
                self._key_deriver(
                    s,
                    iterations,
                    passkey,
                    num_keys=len(fixed_salts),
                    rp=self._str2any(self._r_and_p),
                )
                for s in salts
            )[0]
        )
        fernets = self._fernet_mapper(decipher_keys)
        mfernet = self._get_fernet(fernets)
        encrypted_text = encr_text[len(start_key.encode()) : -len(end_key.encode())]
        if self._aes_encrypted:
            aes_passkey = unpack_tuple(self._aes_passkey)
            mfernet_decrypted = mfernet.decrypt(encrypted_text)
            decipher = AES.new(
                aes_passkey, mode=AES.MODE_CBC, iv=bytes.fromhex(self._aes_iv)
            )
            decr_text = unpad(decipher.decrypt(mfernet_decrypted), self._AES_BSIZE)
        else:
            decr_text = self._validate_token(mfernet, encrypted_text)
        if not decr_text:
            CipherException(
                "The decryption process failed due to the specified salt values, indicating that they are invalid tokens. "
                "An attempt will be made to decrypt using the stored decipher keys.",
                log_method=logger.warning,
            )
            fernets = self._fernet_mapper(org_decipher_keys)
            mfernet = self._get_fernet(fernets)
            decr_text = self._validate_token(mfernet, encr_text)
            if not decr_text:
                raise CipherException(
                    "The decryption process has encountered a complete failure with the specified salt and decipher keys. "
                    "Kindly verify that no modifications have been made to the configuration file."
                )

        decrypted_text = (
            decr_text.decode() if hasattr(decr_text, "decode") else decr_text
        )
        decr_hash = self._calc_str_hash(decrypted_text)
        if hash_value and (decr_hash != hash_value):
            self._failed_hash(hash_value, decr_hash)
        decr_tuple = self._get_subclass(type_file=self._typeis_file)
        return decr_tuple(decrypted_text, hash_value)

    def quick_decrypt(self):
        obj_validator = partial(self._validate_object, type_is=str)
        hash_value = obj_validator(self._hash_value, arg="Hash Value")
        encr_text_str = obj_validator(self._encrypted_data, arg="Encrypted Data")
        if self._typeis_file:
            encr_text_str = self._read_file(encr_text_str)
        encr_text = (
            encr_text_str.encode()
            if hasattr(encr_text_str, "encode")
            else encr_text_str
        )
        primary_key = self._str2any(self._passkey)[1]
        fernet = self._get_fernet(primary_key, fernet_type=Fernet)
        decrypted_text = fernet.decrypt(encr_text).decode()
        if self._typeis_file:
            self._overwrite_file(decrypted_text)
        decr_hash = self._calc_str_hash(decrypted_text)
        if hash_value and (decr_hash != hash_value):
            self._failed_hash(hash_value, decr_hash)
        qdtuple = self._get_subclass(quick_cipher=True, type_file=self._typeis_file)
        return qdtuple(
            self._encrypted_data if self._typeis_file else decrypted_text, hash_value
        )


@overload
def generate_crypto_key(*,
        key_length: int = 32,
        exclude: str = "",
        include_all_chars: bool = False,
        bypass_keylength: bool = False,
        repeat: int = None,
        urlsafe_encoding=False,
    ) -> Union[str, bytes]:
    pass


def generate_crypto_key(**kwargs) -> str:
    """
    ### Generate a Cryptographic Key.
    
    #### Parameters:
        - `key_length` (Union[int, str]): The length of the key. Defaults to 32.
        - `exclude` (Union[str, Iterable]): Characters to exclude from the key generation. \
        Can be a string or an iterable of characters. Defaults to an empty string.
        - `include_all_chars` (bool): If True, include all characters from digits, ascii_letters, and punctuation. \
        Defaults to False.
        - `urlsafe_encoding`: Applies URL-safe Base64 encoding to the generated key
        
        - `repeat` (int): The number of iterations for character cycling. Defaults to 64. \n
            - Note: 
                - `repeat` parameter is used for character cycling from itertools.repeat, \
            and its input is not explicitly needed as its entire purpose is to adjust the key length. \
            If the absolute difference between `repeat` and `key_length` is within a certain threshold (1e5), \
            the `repeat` value will be adjusted as max(max(`repeat`, `key_length`), `threshold`). \n
        >>> if abs(repeat - key_length) <= threshold
        >>> new repeat value -> max(max(repeat, key_length), threshold)
        
    #### Returns:
        - str | bytes: The generated cryptographic key.
        
    #### Raises:
        - CipherException:
            - If conflicting `exclude` and `include_all_chars` arguments are specified
            - If `key_length` is less than default value (32) unless `bypass_keylimit` is passed in.
            - If `key_length` or `repeat` values are greater than the max capacity (1e8).
            
    #### Important Note:
        - The default key includes digits and ascii_letters only.
    """
    return _BaseCryptoEngine._generate_key(**kwargs)


@overload
def quick_encrypt(*,
        text: str = None,
        file: Union[str, Path] = None,
        file_name: str = None,
        export_path: Path = None,
        export_passkey: bool = True,
        backup_file: bool = True,
        passkey: Union[str, int] = None,
        gui_passphrase: bool = False,
        bypass_keylength: bool = False,
        include_all_chars: bool = False,
        exclude_chars: str = None,
        special_keys: bool = None,
    ) -> NamedTuple:
    pass


@_BaseEngine._print_headers(engine="QCipherEngine", method="text encryption")
def quick_encrypt(**kwargs):
    """
    #### Attributes:
        - `text`: str | None: The text to be processed and encrypted.
        - `file`: str | Path | None: The file to be processed and encrypted.
        - `file_name`: str | None: The name of the file containing the encryption details.
        - `export_path`: Path | None: The path where exported files will be stored (default: None).
        - `export_passkey`: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
        - `backup_file`: bool: Flag indicating whether to create a backup file before encryption (default: True).

    #### Cryptographic Attributes:
        - `passkey`: str | int | None: The passphrase or integer to be used for encryption (default: None).
        - `gui_passphrase`: bool: Flag indicating whether to use GUI for passphrase entry (default: False).
        - `bypass_keylength`: bool: Flag indicating whether to bypass key length validation (default: False).
        - `include_all_chars`: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
        - `exclude_chars`: str | None: Characters to exclude during passphrase generation (default: None).
        - `special_keys`: bool | None: If True, uses CipherEngine's custom cryptographic key generation, otherwise uses default keys generated from `Fernet` (default: None).

    #### Class Attributes:
        - `_ALL_CHARS`: str: A string containing all possible characters for passphrase generation.
        - `_MAX_KEYLENGTH`: int: The maximum length for cryptographic keys (32).
        - `_MAX_TOKENS`: int: Maximum number of tokens for cryptographic operations (default: 100,000).
        - `_MAX_CAPACITY`: int: Maximum number of characters to be generated. (For personal use only when using flexible `_generate_key` method.)
        - `_EXECUTOR`: ThreadPoolExecutor: Base executor for all engine classes.

    #### Important Notes:
        - Attributes `include_all_chars` and `exclude_chars` are more customizable features using `secrets.SystemRandom` when generating Fernet keys compared to:

        >>> Fernet.generate_key() # Returns a string of bytes of only containing digits and ascii_letters

        -  `whitespace` ("(space)\\t\\n\\r\\v\\f") are automatically excluded from all available options, as it can interfere with the encryption process when exporting the passkey file.

    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    """
    return CipherEngine(**kwargs).quick_encrypt()


@overload
def quick_decrypt(*,
        text: str = None,
        file: Union[str, Path] = None,
        file_name: str = None,
        export_path: Path = None,
        export_passkey: bool = True,
        backup_file: bool = True,
        passkey: Union[str, int] = None,
        gui_passphrase: bool = False,
        bypass_keylength: bool = False,
        include_all_chars: bool = False,
        exclude_chars: str = None,
        special_keys: bool = None,
    ) -> NamedTuple:
    pass


@_BaseEngine._print_headers(engine="QDecipherEngine", method="text decryption")
def quick_decrypt(**kwargs):
    return DecipherEngine(**kwargs).quick_decrypt()


@overload
def encrypt_file(*,
        file: Union[str, Path] = None,
        file_name: str = None,
        export_path: Path = None,
        export_passkey: bool = True,
        serializer: str = None,
        key_length: int = 32,
        iterations: int = None,
        min_power: bool = False,
        max_power: bool = False,
        backup_file: bool = True,
        advanced_encryption: bool = False,
        passkey: Union[str, int] = None,
        gui_passphrase: bool = False,
        bypass_keylength: bool = False,
        num_of_salts: int = 1,
        include_all_chars: bool = False,
        exclude_chars: str = None,
        special_keys: bool = None,
    ) -> NamedTuple:
    pass


@_BaseEngine._print_headers(engine="CipherEngine", method="file encryption")
def encrypt_file(**kwargs) -> NamedTuple:
    """
    #### Attributes:
        - `file`: str | Path | None: The file to be processed and encrypted.
        - `file_name`: str | None: The name of the file containing the encryption details.
        - `export_path`: Path | None: The path where exported files will be stored (default: None).
        - `export_passkey`: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
        - `serializer`: str | None: The type of serialization to be used for exporting the passkey file ('json' or 'ini').
        - `key_length`: int: The desired key length for Fernet encryption (default: 32).
        - `iterations`: int | None: The number of iterations for key derivation (default: None).
        - `min_power`: bool: Flag indicating whether to enforce minimum passphrase strength (default: False).
        - `max_power`: bool: Flag indicating whether to enforce maximum passphrase strength (default: False).
        - `backup_file`: bool: Flag indicating whether to create a backup file before encryption (default: True).
        - `advanced_encryption`: bool: Flag indicating whether to use advanced encryption features (default: False).

    #### Cryptographic Attributes:
        - `passkey`: str | int | None: The passphrase or integer to be used for encryption (default: None).
        - `gui_passphrase`: bool: Flag indicating whether to use GUI for passphrase entry (default: False).
        - `bypass_keylength`: bool: Flag indicating whether to bypass key length validation (default: False).
        - `num_of_salts`: int: Number of `Fernet` keys to be generated and processed with `MultiFernet`.
        - `include_all_chars`: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
        - `exclude_chars`: str | None: Characters to exclude during passphrase generation (default: None).
        - `special_keys`: bool | None: If True, uses CipherEngine's custom cryptographic key generation, otherwise uses default keys generated from `Fernet` (default: None).

    #### Class Attributes:
        - `_ALL_CHARS`: str: A string containing all possible characters for passphrase generation.
        - `_MAX_KEYLENGTH`: int: The maximum length for cryptographic keys (32).
        - `_MAX_TOKENS`: int: Maximum number of tokens for cryptographic operations (default: 100,000).
        - `_MAX_CAPACITY`: int: Maximum number of characters to be generated. (For personal use only when using flexible `_generate_key` method.)
        - `_EXECUTOR`: ThreadPoolExecutor: Base executor for all engine classes.

    #### Important Notes:
        - Attributes `include_all_chars` and `exclude_chars` are more customizable features using `secrets.SystemRandom` when generating Fernet keys compared to:

        >>> Fernet.generate_key() # Returns a string of bytes of only containing digits and ascii_letters

        -  `whitespace` ("(space)\\t\\n\\r\\v\\f") are automatically excluded from all available options, as it can interfere with the encryption process when exporting the passkey file.

    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    """
    return CipherEngine(**kwargs).encrypt_file()


@overload
def decrypt_file(*,
        file: Union[str, Path] = None,
        file_name: str = None,
        export_path: Path = None,
        export_passkey: bool = True,
        serializer: str = None,
        passkey: Union[str, int] = None,
        gui_passphrase: bool = False,
        bypass_keylength: bool = False,
        num_of_salts: int = 1,
        include_all_chars: bool = False,
        exclude_chars: str = None,
        special_keys: bool = None,
    ) -> NamedTuple:
    pass


@_BaseEngine._print_headers(engine="DecipherEngine", method="file decryption")
def decrypt_file(**kwargs) -> NamedTuple:
    return DecipherEngine(**kwargs).decrypt_file()


@overload
def encrypt_text(*,
        text: str = None,
        file_name: str = None,
        export_path: Path = None,
        export_passkey: bool = True,
        serializer: str = None,
        iterations: int = None,
        min_power: bool = False,
        max_power: bool = False,
        advanced_encryption: bool = False,
        passkey: Union[str, int] = None,
        key_length: int = 32,
        gui_passphrase: bool = False,
        bypass_keylength: bool = False,
        num_of_salts: int = 1,
        include_all_chars: bool = False,
        exclude_chars: str = None,
        special_keys: bool = None,
    ) -> NamedTuple:
    pass


@_BaseEngine._print_headers(engine="CipherEngine", method="text encryption")
def encrypt_text(**kwargs) -> NamedTuple:
    """
    #### Attributes:
        - `text`: str | None: The text to be processed and encrypted.
        - `file_name`: str | None: The name of the file containing the encryption details.
        - `export_path`: Path | None: The path where exported files will be stored (default: None).
        - `export_passkey`: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
        - `serializer`: str | None: The type of serialization to be used for exporting the passkey file ('json' or 'ini').
        - `iterations`: int | None: The number of iterations for key derivation (default: None).
        - `min_power`: bool: Flag indicating whether to enforce minimum passphrase strength (default: False).
        - `max_power`: bool: Flag indicating whether to enforce maximum passphrase strength (default: False).
        - `advanced_encryption`: bool: Flag indicating whether to use advanced encryption features (default: False).

    #### Cryptographic Attributes:
        - `passkey`: str | int | None: The passphrase or integer to be used for encryption (default: None).
        - `key_length`: int: The desired key length for Fernet encryption (default: 32).
        - `gui_passphrase`: bool: Flag indicating whether to use GUI for passphrase entry (default: False).
        - `bypass_keylength`: bool: Flag indicating whether to bypass key length validation (default: False).
        - `num_of_salts`: int: Number of `Fernet` keys to be generated and processed with `MultiFernet`.
        - `include_all_chars`: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
        - `exclude_chars`: str | None: Characters to exclude during passphrase generation (default: None).
        - `special_keys`: bool | None: If True, uses CipherEngine's custom cryptographic key generation, otherwise uses default keys generated from `Fernet` (default: None).

    #### Class Attributes:
        - `_ALL_CHARS`: str: A string containing all possible characters for passphrase generation.
        - `_MAX_KEYLENGTH`: int: The maximum length for cryptographic keys (32).
        - `_MAX_TOKENS`: int: Maximum number of tokens for cryptographic operations (default: 100,000).
        - `_MAX_CAPACITY`: int: Maximum number of characters to be generated. (For personal use only when using flexible `_generate_key` method.)
        - `_EXECUTOR`: ThreadPoolExecutor: Base executor for all engine classes.

    #### Important Notes:
        - Attributes `include_all_chars` and `exclude_chars` are more customizable features using `secrets.SystemRandom` when generating Fernet keys compared to:

        >>> Fernet.generate_key() # Returns a string of bytes of only containing digits and ascii_letters

        -  `whitespace` ("(space)\\t\\n\\r\\v\\f") are automatically excluded from all available options, as it can interfere with the encryption process when exporting the passkey file.

    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    """
    return CipherEngine(**kwargs).encrypt_text()


@overload
def decrypt_text(*,
        ciphertuple: NamedTuple,
        passkey_file: Union[str, Path],
        manual_kwgs: dict[str, Any],
    ) -> NamedTuple:
    pass


@_BaseEngine._print_headers(engine="DecipherEngine", method="text decryption")
def decrypt_text(**kwargs) -> NamedTuple:
    """
    #### Attributes:
        - `ciphertuple` (NamedTuple): The tuple generated from any encryption process to be used for decryption.
        - `passkey_file`: str | Path: The path to the file containing the encryption details.
        - `manual_kwgs`: dict: Dictionary containing encryption data to be used for decryption.

    #### Returns:
        - NamedTuple: Tuple containing information about the decryption process.
    """
    return DecipherEngine(**kwargs).decrypt_text()


quick_decrypt.__doc__ = decrypt_file.__doc__ = decrypt_text.__doc__


# XXX Metadata Information
METADATA = {
    "version": (__version__ := "0.4.1"),
    "license": (__license__ := "Apache License, Version 2.0"),
    "url": (__url__ := "https://github.com/yousefabuz17/CipherEngine"),
    "author": (__author__ := "Yousef Abuzahrieh <yousef.zahrieh17@gmail.com"),
    "copyright": (__copyright__ := f"Copyright © 2024, {__author__}"),
    "summary": (
        __summary__ := "Comprehensive cryptographic module providing file and text encryption, key generation, and rotation of decipher keys for additional security."
    ),
    "doc": __doc__,
}


__all__ = (
    "METADATA",
    "CipherEngine",
    "DecipherEngine",
    "CipherException",
    "generate_crypto_key",
    "encrypt_file",
    "decrypt_file",
    "encrypt_text",
    "decrypt_text",
    "quick_encrypt",
    "quick_decrypt",
)

if __name__ == "__main__":
    from cli_options import cli_parser

    try:
        cli_parser()
    except NameError:
        # If missing markdown files for 'cli_options'.
        pass
