import ast
import os
import re
import sys
import math
import json
import base64
import hashlib
import shutil
import logging
import operator
import configparser
from pathlib import Path
from logging import Logger
from datetime import datetime
from functools import partial
from argparse import ArgumentParser
from random import SystemRandom
from itertools import cycle, islice, tee
from dataclasses import dataclass, field
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from string import digits, punctuation, ascii_letters, whitespace
from typing import (
    Any,
    AnyStr,
    Dict,
    Iterable,
    NamedTuple,
    TypeVar,
    Optional,
    Union,
    Literal,
    NoReturn,
    FrozenSet,
)
from cryptography.fernet import Fernet, MultiFernet


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

    if write_log:
        file_handler = logging.FileHandler(**_handler_kwgs)
        file_handler.setFormatter(formatter)
        _logger.addHandler(file_handler)

    if level != logging.DEBUG:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        _logger.addHandler(stream_handler)

    return _logger


logger = get_logger(level=logging.INFO, write_log=True)
B = TypeVar("B", bool, None)
I = TypeVar("I", int, None)
N = TypeVar("N", NamedTuple, NoReturn)
P = TypeVar("P", Path, str)


class CipherException(BaseException):
    def __init__(self, *args, log_method: logger = logger.critical):
        self.log_method = log_method
        super().__init__(*args)
        self.log_method(*args)


@dataclass(kw_only=True)
class _BaseKeyEngine:
    """
    Base crypotgraphic class for the CipherEngine hierarchy, providing common attributes and functionality \
    for generating cryptographic keys.
    """

    num_of_keys: int = field(repr=False, default=None)
    exclude_chars: str = field(repr=False, default=None)
    include_all_chars: Optional[B] = field(repr=False, default=False)
    _MAX_TOKENS = int(1e5)
    _MAX_KEYLENGTH: int = 32
    _ALL_CHARS: str = digits + punctuation + ascii_letters
    _MAX_CAPACITY = int(1e8)
    _EXECUTOR = ThreadPoolExecutor()

    def _validate_numkeys(cls, __num: int):
        if __num:
            num_keys = cls._validate_object(
                __num, type_is=int, arg="Number of Crypto Keys"
            )
            if num_keys >= cls._MAX_TOKENS:
                CipherException(
                    f"WARNING: The specified 'num_of_keys' surpasses the recommended limit for {MultiFernet.__name__}. "
                    "Adding a large number of keys can result in computaitonal power and increased ciphertext size. "
                    f"It is recommended to keep the number of keys within 2 <= x <= 5 "
                    "for efficient key rotation and optimal performance.\n"
                    f"Specified Amount: {num_keys:_}\n"
                    f"Recommended Amount: 5",
                    log_method=logger.warning,
                )
            return num_keys
        else:
            raise CipherException(
                "Number of keys to be generated must be of value >=1. "
                f"The specified value is considered invalid ({__num})"
            )

    @staticmethod
    def _base64_key(__key: str):
        try:
            return base64.urlsafe_b64encode(__key)
        except AttributeError as attr_error:
            raise CipherException(
                f"Failed to derive encoded bytes from {__key!r}. " f"\n{attr_error}"
            )

    @property
    def gen_keys(self):
        if self.num_of_keys:
            self.num_of_keys = self._validate_numkeys(self.num_of_keys)
        else:
            self.num_of_keys = 5
        passkeys = self._EXECUTOR.map(
            lambda _k: self._generate_key(
                key_length=32,
                exclude=self.exclude_chars,
                include_all_chars=self.include_all_chars,
                urlsafe_encoding=True,
            ),
            range(1, self.num_of_keys + 1),
        )
        return passkeys

    @classmethod
    def _get_fernet_keys(cls, **kwargs):
        return _BaseKeyEngine(**kwargs).gen_keys

    def _get_fernet(self, __keys=None):
        keys = __keys or self._EXECUTOR.map(Fernet, self.gen_keys)
        return MultiFernet(tuple(keys))

    @staticmethod
    def _validate_object(
        __obj: Any, type_is: type = int, arg: str = "Argument"
    ) -> int | str | list[str] | Path | Optional[False] | NoReturn:
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

        possible_instances = (TypeError, ValueError, SyntaxError)

        if type_is is Any:
            type_is = type(__obj)

        if type_is in (int, float):
            try:
                _obj = int(__obj)
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
            - Whitespace ('(space)\t\n\r\v\f') is automatically excluded.
            - To exclude additional characters, provide them as a string in the `exclude` parameter.
        """
        check_str = cls._validate_object(__string, type_is=str, arg="Char")
        full_string = "".join(check_str)
        filter_out = whitespace + exclude
        string_filtered = full_string.translate(str.maketrans("", "", filter_out))
        return string_filtered

    @staticmethod
    def _exclude_type(__key: str = "punct", return_dict: bool = False) -> str:
        """
        ### Exclude specific character sets based on the provided key.

        #### Parameters:
        - __key (str): The key to select the character set to exclude.
        - return_dict (bool): If True, returns the dicitonary containing all possible exluce types.

        #### Returns:
        - str: The selected character set based on the key to be excluded from the generated passkey.

        #### Possible values for __key:
        - 'digits': Excludes digits (0-9).
        - 'punct': Excludes punctuation characters.
        - 'ascii': Excludes ASCII letters (both uppercase and lowercase).
        - 'digits_punct': Excludes both digits and punctuation characters.
        - 'ascii_punct': Excludes both ASCII letters and punctuation characters.
        - 'digits_ascii': Excludes both digits and ASCII letters.
        - 'digits_ascii_lower': Excludes both digits and lowercase ASCII letters.
        - 'digits_ascii_upper': Excludes both digits and uppercase ASCII letters.
        - 'punct_ascii_lower': Excludes both punctuation characters and lowercase ASCII letters.
        - 'punct_ascii_upper': Excludes both punctuation characters and uppercase ASCII letters.
        - 'ascii_lower_punct': Excludes both lowercase ASCII letters and punctuation characters.
        - 'ascii_upper_punct': Excludes both uppercase ASCII letters and punctuation characters.
        - 'digits_ascii_lower_punct': Excludes digits, lowercase ASCII letters, and punctuation characters.
        - 'digits_ascii_upper_punct': Excludes digits, uppercase ASCII letters, and punctuation characters.
        """
        all_chars = {
            "digits": digits,
            "punct": punctuation,
            "ascii": ascii_letters,
            "digits_punct": digits + punctuation,
            "ascii_punct": ascii_letters + punctuation,
            "digits_ascii": digits + ascii_letters,
            "digits_ascii_lower": digits + ascii_letters.lower(),
            "digits_ascii_upper": digits + ascii_letters.upper(),
            "punct_ascii_lower": punctuation + ascii_letters.lower(),
            "punct_ascii_upper": punctuation + ascii_letters.upper(),
            "ascii_lower_punct": ascii_letters.lower() + punctuation,
            "ascii_upper_punct": ascii_letters.upper() + punctuation,
            "digits_ascii_lower_punct": digits + ascii_letters.lower() + punctuation,
            "digits_ascii_upper_punct": digits + ascii_letters.upper() + punctuation,
        }
        if return_dict:
            return all_chars
        return all_chars.get(__key)

    @classmethod
    def _sig_larger(cls, *args) -> N:
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
    ) -> str:
        if all((exclude, include_all_chars)):
            raise CipherException(
                "Cannot specify both 'exclude' and 'include_all_chars' arguments."
            )

        if repeat:
            repeat_val = cls._validate_object(repeat, type_is=int, arg="repeat")
        else:
            repeat_val = cls._MAX_TOKENS

        key_length = cls._validate_object(key_length, type_is=int, arg="Key Length")
        if not bypass_keylength and key_length < cls._MAX_KEYLENGTH:
            raise CipherException(
                f"key_length must be of value >={cls._MAX_KEYLENGTH}.\n"
                f"Specified Key Length: {key_length}"
            )

        if any((repeat_val >= cls._MAX_CAPACITY, key_length >= cls._MAX_CAPACITY)):
            raise CipherException(
                f"The specified counts surpasses the computational capacity required for {cls.__name__!r}. "
                "It is recommended to use a count of 32 <= x <= 256, considering the specified 'key_length'. \n"
                f"Max Capacity: {cls._MAX_CAPACITY:_}\n"
                f"Character Repeat Count: {repeat_val:_}"
            )

        threshold = cls._sig_larger(key_length, int(repeat_val))
        if not threshold.status:
            cls._MAX_TOKENS = threshold.threshold
            CipherException(
                "The specified values for 'key_length' or 'iterations' (repeat) exceeds the number of characters that can be cycled during repetition."
                f" Higher values for 'max_tokens' count is recommended for better results ('max_tokens' count is now {cls._MAX_TOKENS}).",
                log_method=logger.warning,
            )

        slicer = lambda *args: "".join(islice(*args, cls._MAX_TOKENS))
        all_chars = slicer(cycle(cls._ALL_CHARS))
        filtered_chars = cls._filter_chars(all_chars, exclude=punctuation)

        if include_all_chars:
            filtered_chars = all_chars

        if exclude:
            exclude_obj = cls._validate_object(
                exclude, type_is=str, arg="exclude_chars"
            )
            filter_char = partial(cls._filter_chars, all_chars)
            exclude_type = cls._exclude_type(exclude_obj)
            filtered_chars = (
                filter_char(exclude=exclude)
                if not exclude_type
                else filter_char(exclude=exclude_type)
            )

        passkey = SystemRandom().sample(
            population=filtered_chars, k=min(key_length, len(filtered_chars))
        )
        crypto_key = "".join(passkey)
        if urlsafe_encoding:
            crypto_key = cls._base64_key(crypto_key.encode())
        return crypto_key

    @classmethod
    def _fernet_mapper(cls, __keys):
        return cls._EXECUTOR.map(Fernet, __keys)


@dataclass(kw_only=True)
class _BaseEngine(_BaseKeyEngine):
    """
    Base class for the CipherEngine hierarchy, providing common attributes and functionality for encryption.
    """

    # XXX Shared attributes across all engines.
    overwrite_file: Optional[B] = field(repr=False, default=False)
    identifiers: Optional[Iterable[str]] = field(repr=False, default=None)
    _AES: str = "aes"
    _DEC: str = "dec"
    _INI: str = "ini"
    _JSON: str = "json"
    _PRE_ENC: str = "encrypted"
    _PRE_DEC: str = "decrypted"

    def _get_serializer(self):
        serializer = self._validate_object(
            self.serializer, type_is=str, arg="Serializer"
        )
        return self._compiler(["json"], serializer, escape_k=False)

    @staticmethod
    def _new_parser() -> configparser.ConfigParser:
        return configparser.ConfigParser()

    @classmethod
    def _failed_hash(cls, org_hash: bytes, second_hash: bytes) -> CipherException:
        raise CipherException(
            "The discrepancy in hashed values points to a critical integrity issue, suggesting potential data loss. "
            "Immediate data investigation and remedial action are strongly advised. "
            f"\nOriginal Hash: {org_hash}"
            f"\nDecrypted Hash: {second_hash}"
        )

    @staticmethod
    def _template_parameters() -> FrozenSet:
        """All key sections for configuration file."""
        return frozenset(
            {
                "encrypted_text",
                "encrypted_file",
                "decipher_keys",
                "fernets",
                "hash_value",
                "id1",
                "id2",
                "original_text",
                "original_file",
            }
        )

    @staticmethod
    def _check_headers(__data: str, headers, msg="", method=all, include_not=False):
        """Checks whether specified data contains the correct encryption identifiers."""
        start, end = headers
        try:
            result = method((__data.startswith(start), __data.endswith(end)))
        except TypeError:
            result = method(
                (__data.startswith(start.decode()), __data.endswith(end.decode()))
            )
        if include_not and not result:
            raise CipherException(msg)
        elif not include_not and result:
            raise CipherException(msg)

    def _new_template(self, **kwargs) -> Dict:
        """
        #### \
        This method creates a dynamic template incorporating encryption parameters and security details \
        suitable for writing encrypted data to a file. \
        The generated template can later be employed in the decryption process.
        """
        # XXX CIPHER_INFO
        org_str = "original_{}".format("file" if "encrypted_file" in kwargs else "text")
        org_data = kwargs.pop(org_str)
        encr_str = "encrypted_{}".format(
            "file" if "encrypted_file" in kwargs else "text"
        )
        encr_data = kwargs.pop(encr_str)
        decipher_keys = kwargs.pop(decipher_str := ("decipher_keys"))
        _fernets = kwargs.pop("fernets", None)  # Only for CipherTuples
        return {
            "CIPHER_INFO": {
                org_str: org_data,
                encr_str: encr_data,
            },
            "SECURITY_PARAMS": {**kwargs, decipher_str: decipher_keys},
        }

    @staticmethod
    def _format_file(__file: P) -> str:
        time_now = datetime.now()
        formatted_time = time_now.strftime("%Y-%m-%dT%I-%M-%S%p-")
        return (__file.parent / formatted_time).as_posix() + (f"backup-{__file.name}")

    @staticmethod
    def _bytes_read(__file: P) -> bytes:
        with open(__file, mode="rb") as _file:
            _text = _file.read()
        return _text

    @staticmethod
    def none_generator(__data, default=None):
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
    def _ciphertuple(cls, *args, type_file=False):
        """
        #### ('decipher_key',
        #### 'encrypted_text/file', 'fernets', 'hash_value',
        #### 'id1', 'id2', 'original_text/file')
        """
        parameters = cls._template_parameters()
        specific_params = (
            k
            for k in parameters
            if (type_file and not k.endswith("text"))
            or (not type_file and not k.endswith("file"))
        )
        ordered_params = sorted(specific_params)
        args = cls.none_generator(ordered_params) if not args else args
        return cls._create_subclass(
            "CipherTuple",
            field_names=ordered_params,
            values=args,
            field_doc="Primary NamedTuple \
                                            for storing encryption details.",
        )

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

    @staticmethod
    def _terminal_size() -> int:
        return shutil.get_terminal_size().columns

    @classmethod
    def _replace_file(cls, __file, overwrite=False):
        new_path = __file.parent
        if overwrite:
            new_file = new_path / __file.stem
            CipherException(f"Overwriting {__file!r}...", log_method=logger.info)
            os.remove(__file)
        else:
            if __file.is_file():
                prefix = cls._PRE_ENC
                _name = __file.stem.removeprefix(prefix)
                if re.search(r"\.", _name):
                    _name = __file.stem.split(".")[0]
                new_file = __file.parent / f"{prefix}_{_name}"
                return new_file

    @classmethod
    def _calc_file_hash(cls, __file: P) -> str:
        """
        Calculate the SHA-256 hash of the content in the specified file.

        Parameters:
        - file_path (str): The path to the file for which the hash is to be calculated.

        Returns:
        - str: The SHA-256 hash value as a hexadecimal string.
        """
        file = cls._validate_file(__file)
        sha256_hash = hashlib.sha256()
        with open(__file, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @classmethod
    def _calc_str_hash(cls, __text: str = None):
        """
        Calculate the SHA-256 hash of the provided text.

        Parameters:
        - text (str): The input text for which the hash is to be calculated.

        Returns:
        - str: The SHA-256 hash value as a hexadecimal string.
        """
        hash_ = hashlib.sha256()
        hash_.update(__text.encode())
        return hash_.hexdigest()

    @classmethod
    def _parse_config(
        cls, __config: P, *, section: str = "SECURITY_PARAMS", section_key: str
    ) -> Union[str, Any]:
        file_suffix = __config.suffix.lstrip(".")
        try:
            if file_suffix == cls._JSON:
                cparser = json.load(open(__config))
            else:
                cparser = cls._new_parser()
                cparser.read(__config)
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
                f"An unexpected error occurred while attempting to read the configuration file {__config.name}. "
                f"The decryption algorithm is designed to work with its original values. "
                "Please note that if the passphrase contains special characters, it may result in decryption issues."
            )
        return sec_val

    @classmethod
    def _get_identifiers(cls, __identifiers: Iterable[str]):
        if __identifiers:
            identifiers = cls._validate_object(
                __identifiers, type_is=Iterable, arg="Encryption Identifier"
            )
        else:
            base_identifier = "-----{} CIPHERENGINE CRYPTOGRAPHIC ENCRYPTED KEY-----"
            identifiers = (
                base_identifier.format("BEGIN"),
                base_identifier.format("END"),
            )
        return tuple(id_.encode() for id_ in identifiers)

    @property
    def _identifiers(self):
        headers = "" if not hasattr(self, "identifiers") else self.identifiers
        return self._get_identifiers(headers)

    @classmethod
    def _validate_ciphertuple(cls, __ctuple: NamedTuple) -> N:
        all_parameters = cls._template_parameters()
        # ** isinstance(__obj, CipherTuple)?
        if hasattr(__ctuple, "_fields") and all(
            (
                isinstance(__ctuple, tuple),
                isinstance(__ctuple._fields, tuple),
                hasattr(__ctuple, "__module__"),
                __ctuple.__module__ == "CipherTuple",
            )
        ):
            ctuple_set = set(__ctuple._asdict())
            ctuple_paramters = all_parameters & ctuple_set
            try:
                for param in ctuple_paramters:
                    param_attr = getattr(__ctuple, param)
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
                f"{__ctuple!r} must be of type {NamedTuple.__name__!r}"
            )

        return __ctuple

    def _create_backup(self, __file: P) -> None:
        CEinfo = partial(CipherException, log_method=logger.info)
        backup_path = __file.parent / f"backup/{__file.name}"
        formatted_bkp = _BaseEngine._format_file(backup_path)
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
        suffix: bool = "ini",
        data: AnyStr = "",
        mode: str = "w",
        parser: configparser = None,
        reason: str = "",
    ) -> None:
        new_file = Path(__file).with_suffix(f".{suffix}")
        with open(new_file, mode=mode) as _file:
            if parser:
                parser.write(_file)
            else:
                _file.write(data)
            p_string = partial(
                "{file!r} has successfully been {reason} to {path!r}".format,
                file=_file.name,
                path=new_file.absolute(),
            )
            CipherException(
                p_string(reason=reason or "written"), log_method=logger.info
            )
        return

    @classmethod
    def _compiler(
        cls, __defaults, __k, escape_default=True, escape_k=True, search=True
    ) -> str:
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

    file: Optional[P] = field(repr=False, default=None)
    file_name: Optional[str] = field(repr=False, default=None)
    text: Optional[P] = field(repr=False, default=None)
    export_path: Optional[P] = field(repr=False, default=None)
    serializer: Literal["json", "ini"] = field(repr=True, default="ini")
    backup_file: Optional[B] = field(repr=False, default=True)
    export_passkey: Optional[B] = field(repr=False, default=True)
    special_keys: Optional[B] = field(repr=False, default=True)

    def __post_init__(self):
        self._serializer = self._get_serializer()
        self._gen_keys = self._get_passkeys()
        self._file = None if not self.file else self._validate_file(self.file)
        self._text = (
            None
            if not self.text
            else self._validate_object(self.text, type_is=str, arg="Text")
        )

    def _get_passkeys(self):
        get_keys = partial(self._get_fernet_keys, num_of_keys=self.num_of_keys)
        if self.special_keys:
            return get_keys(exclude_chars=self.exclude_chars)
        else:
            return get_keys()

    def _export_passkey(self, *, parser, passkey_file, data) -> None:
        passkey_suffix = self._INI
        write_func = partial(self._write2file, passkey_file, reason="exported")
        write2file = partial(write_func, suffix=passkey_suffix, parser=parser)

        def json_serializer():
            new_data = json.dumps(data, indent=2, ensure_ascii=False)
            passkey_suffix = self._JSON
            write2file = partial(write_func, suffix=passkey_suffix, data=new_data)
            return write2file

        if self._serializer:
            write2file = json_serializer()

        try:
            parser.update(**data)
        except ValueError:
            CipherException(
                f"Passphrases containing special characters are not suitable for .INI configurations. "
                "Serializing in JSON (.json) format to accommodate special characters.",
                log_method=logger.error,
            )
            write2file = json_serializer()

        if self.export_passkey:
            write2file()

    def _base_error(self, __data=None):
        if not __data:
            __data = "the data"
        return (
            f"{self.__class__.__name__.upper()} encrypter identifications detected signaling that {__data!r} is already encrypted. "
            "\nRe-encrypting it poses a significant risk of resulting in inaccurate decryption, potentially leading to irreversible data corruption. "
            "\nIt is crucial to decrypt the data first before attempting any further encryption."
            "\n\nStrictly limit the encryption process to once per object for each subsequent decryption to safeguard against catastrophic data loss."
        )

    def encrypt_file(self):
        if not self._file:
            raise CipherException(f"{self._text!r} cannot be null for encryption.")
        org_file = self._file
        hash_val = self._calc_file_hash(org_file)
        plain_btext = self._bytes_read(org_file)
        start_key, end_key = self._identifiers
        self._check_headers(
            plain_btext, self._identifiers, msg=self._base_error(org_file), method=any
        )

        if self.backup_file or self.overwrite_file:
            self._create_backup(org_file)

        if self.overwrite_file:
            encr_file = org_file.parent / org_file.stem
            CipherException(f"Overwriting {org_file!r}...", log_method=logger.info)
            os.remove(org_file)
        else:
            if org_file.is_file():
                prefix = self._PRE_ENC
                _name = org_file.stem.removeprefix(prefix)
                if re.search(r"\.", _name):
                    _name = org_file.stem.split(".")[0]
                encr_file = org_file.parent / f"{prefix}_{_name}"

        start_key, end_key = self._identifiers
        keys = tee(self._gen_keys)
        fernet = self._get_fernet(tuple(self._fernet_mapper(keys[0])))
        encr_file = Path(encr_file).with_suffix(f".{self._AES}")
        encryption_data = start_key + fernet.encrypt(plain_btext) + end_key
        self._write2file(
            encr_file,
            suffix=self._AES,
            mode="wb",
            data=encryption_data,
            reason="exported",
        )
        cparser = self._new_parser()
        passkey_name = self.file_name or Path(f"{encr_file.stem}_passkey")
        passkey_file = org_file.parent / passkey_name
        ciphertuple = self._ciphertuple(
            tuple(i.decode() for i in keys[1]),
            encr_file.as_posix(),
            fernet._fernets,
            hash_val,
            start_key.decode(),
            end_key.decode(),
            org_file.as_posix(),
            type_file=True,
        )
        encr_data = self._new_template(**ciphertuple._asdict())
        if self.export_passkey:
            self._export_passkey(
                parser=cparser, passkey_file=passkey_file, data=encr_data
            )
        return ciphertuple

    def encrypt_text(self):
        if not self._text:
            raise CipherException(f"{self._text!r} cannot be null for encryption.")

        keys = tee(self._gen_keys)
        hash_val = self._calc_str_hash(self._text)
        self._check_headers(
            self._text, self._identifiers, msg=self._base_error(), method=any
        )
        start_key, end_key = self._identifiers
        fernet = self._get_fernet(tuple(self._fernet_mapper(keys[0])))
        encrypted_text = start_key + fernet.encrypt(self._text.encode()) + end_key
        ciphertuple = self._ciphertuple(
            tuple(i.decode() for i in keys[1]),
            encrypted_text.decode(),
            fernet._fernets,
            hash_val,
            start_key.decode(),
            end_key.decode(),
            self._text,
        )
        if self.export_passkey:
            _file = Path(self.file_name or "ciphertext_passkey.ini")
            cparser = self._new_parser()
            ctuple_data = self._new_template(**ciphertuple._asdict())
            if self.export_path:
                _file = Path(self.export_path) / _file
            self._export_passkey(parser=cparser, passkey_file=_file, data=ctuple_data)
        return ciphertuple


@dataclass(kw_only=True)
class DecipherEngine(_BaseEngine):
    """
    DecipherEngine is a class designed to decrypt data encrypted through the CipherEngine.
    This class specifically operates with (configuration files | CipherTuples) generated by the CipherEngine during the encryption process.
    """

    ciphertuple: Optional[NamedTuple] = field(repr=False, default=None)
    passkey_file: Optional[P] = field(repr=False, default=None)

    def __post_init__(self):
        # ** For configuration files (.INI | .JSON)
        if all((self.passkey_file, self.ciphertuple)):
            raise CipherException(
                "Cannot simultaneously specify 'ciphertuple' and 'passkey_file'."
            )

        if self.passkey_file:
            self._passkey_file = self._validate_file(self.passkey_file)
            cparser_func = partial(self._parse_config, self._passkey_file)
            self._decipher_keys = cparser_func(section_key="decipher_keys")
            self._hash_value = cparser_func(section_key="hash_value")
            self._start_key = cparser_func(section_key="id1")
            self._end_key = cparser_func(section_key="id2")
            sec_getter = lambda sec_key: cparser_func(
                section="CIPHER_INFO", section_key=sec_key
            )
            self._encrypted_text = sec_getter(sec_key="encrypted_text")
            self._encrypted_file = sec_getter(sec_key="encrypted_file")

        # ** For CipherTuple instances.
        if self.ciphertuple:
            self._ciphertuple = self._validate_ciphertuple(self.ciphertuple)

    @classmethod
    def _get_subclass(cls, type_file=False):
        decr_type = "decrypted_{}".format("text" if not type_file else "file")
        return cls._create_subclass(
            "DecipherTuple", field_names=(decr_type, "hash_value")
        )

    @classmethod
    def _str2fbytes(cls, __keys=None):
        if isinstance(__keys, str):
            __keys = ast.literal_eval(__keys)
        return (Fernet(k.encode() if hasattr(k, "encode") else k) for k in __keys)

    def _base_error(self, __data=None):
        if not __data:
            __data = "provided"
        return (
            f"The data {__data!r} lacks the required identifiers. "
            f"\n{self.__class__.__name__.upper()}'s decryption algorithm only operates with data containing its designated identifiers. "
            f"\nEncryption algorithms identifiers:\n{self._identifiers}"
        )

    def decrypt_file(self):
        config_path = self._passkey_file
        hashed_value = self._parse_config(config_path, section_key="hash_value")
        encrypted_file = self._validate_file(self._encrypted_file)
        bytes_data = self._bytes_read(encrypted_file)
        self._check_headers(
            bytes_data,
            self._identifiers,
            msg=self._base_error(encrypted_file),
            method=all,
            include_not=True,
        )
        default_suffix = self._PRE_DEC
        start_key, end_key = self._identifiers
        decipher_keys = self._str2fbytes(self._decipher_keys)
        encrypted_data = bytes_data[len(start_key) : -len(end_key)]
        fernet = self._get_fernet(tuple(decipher_keys))
        decrypted_data = fernet.decrypt(encrypted_data)
        if self.overwrite_file:
            default_suffix = encrypted_file.name.split(".")[-1]
            decrypted_file = encrypted_file.as_posix()
            os.remove(encrypted_file)
        else:
            if encrypted_file.is_file():
                prefix = default_suffix
                _name = encrypted_file.stem.removeprefix(prefix)
                if re.search(r"\.", _name):
                    _name = encrypted_file.stem.split(".")[0]
                decrypted_file = (
                    encrypted_file.parent / f"{prefix}_{_name}"
                ).as_posix()

        decrypted_file = Path(decrypted_file)
        self._write2file(
            decrypted_file,
            suffix=default_suffix,
            mode="wb",
            data=decrypted_data,
            reason="decrypted",
        )

        decrypted_hash = self._calc_file_hash(
            decrypted_file.with_suffix("." + default_suffix)
        )
        if hashed_value != decrypted_hash:
            self._failed_hash(hashed_value, decrypted_hash)
        decr_tuple = self._get_subclass(type_file=True)
        return decr_tuple(decrypted_file, decrypted_hash)

    def decrypt_text(self):
        if self.ciphertuple:
            self._validate_ciphertuple(self.ciphertuple)
            encr_text = self.ciphertuple.encrypted_text
            decipher_keys = self.ciphertuple.fernets
            hash_value = self.ciphertuple.hash_value
            start_key = self.ciphertuple.id1
            end_key = self.ciphertuple.id2
        else:
            obj_validator = partial(self._validate_object, type_is=str)
            encr_text = obj_validator(self._encrypted_text, arg="Encrypted Text")
            decipher_keys = self._str2fbytes(self._decipher_keys)
            hash_value = obj_validator(self._hash_value, arg="Hash Value")
            start_key = obj_validator(
                self._start_key, arg="Beginning Encryption Header"
            )
            end_key = obj_validator(self._end_key, arg="Ending Encryption Header")

        self._check_headers(
            encr_text,
            (start_key, end_key),
            msg=self._base_error(),
            method=all,
            include_not=True,
        )
        encr_text = encr_text[len(start_key.encode()) : -len(end_key.encode())]
        fernet = self._get_fernet(tuple(decipher_keys))
        decr_text = fernet.decrypt(encr_text.encode()).decode()
        decr_hash = self._calc_str_hash(decr_text)
        if hash_value and (decr_hash != hash_value):
            self._failed_hash(hash_value, decr_hash)
        decr_tuple = self._get_subclass()
        return decr_tuple(decr_text, hash_value)


def generate_crypto_key(**kwargs) -> str:
    """
    ### Generate a Cryptographic Key.
    
    #### Parameters:
        - `key_length` (Union[int, str]): The length of the key. Defaults to 32.
            - Important Note: key_length soley depends on the max_tokens count.
            Length must be greater than max_tokens count.
        - `exclude` (Union[str, Iterable]): Characters to exclude from the key generation. \
        Can be a string or an iterable of characters. Defaults to an empty string.
        - `include_all_chars` (bool): If True, include all characters from digits, ascii_letters, and punctuation. \
        Defaults to False.
        - `urlsafe_encoding`: Applies URL-safe Base64 encoding to the passkey
        - `repeat` (int): The number of iterations for character cycling. Defaults to 64. \n
            - `Note`: 'repeat' parameter is used for character cycling from itertools.repeat, \
            and its input is not explicitly needed as its entire purpose is to adjust the key length. \
            If the absolute difference between 'repeat' and 'key_length' is within a certain threshold (1e5), \
            the `repeat` value will be adjusted as max(max(`repeat`, key_length), `threshold`). \n
        >>> if abs(repeat - key_length) <= threshold
        >>> new repeat value -> max(max(repeat, key_length), threshold)
        
    #### Returns:
        - str | bytes: The generated cryptographic key.
        
    #### Raises:
        - CipherException:
            - If conflicting exclude and include_all_chars arguments are specified
            - If `key_length` is less than default value (32) unless `bypass_length_limit` is passed in.
            - If `key_length` or `repeat` values are greater than the max capacity (1e8).
            
    #### Important Note:
        - The default key includes digits and ascii_letters only.
    """
    return _BaseKeyEngine._generate_key(**kwargs)


def encrypt_file(**kwargs):
    """
    #### Attributes:
        - `text` | `file`: str | None: The data to be processed and encrypted (default: None).
        - `file_name`: str | None: The name of the file containing the encryption details.
        - `export_path`: Path | None: The path where exported files will be stored (default: None).
        - `export_passkey`: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
        - `overwrite_file`: bool | None: Flag indicating whether to overwrite the original file during encryption (default: False).
        - `backup_file`: bool: Flag indicating whether to create a backup of the original file (default: True).
        - `serializer`: str: The type of serialization to be used for exporting the passkey file ('json' or 'ini').
        - `identifiers`: Iterable[str]: Specifiy a custom encryption identifier for the start and end of the encryption key (default: default settings.)
        
    #### Cryptographic Attributes:
        - `num_of_keys`: int: Number of `Fernet` keys to be generated and processed with `MultiFernet`. 
        - `include_all_chars`: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
        - `exclude_chars`: Union[list, str]: Characters to exclude during passphrase generation (default: None).
        - `special_keys`: bool: If True, uses CipherEngines custom cryptographic key generation, \
            otherwise uses default keys generated from `Fernet`.
    
    #### Class Attributes:
        - `_ALL_CHARS`: str: A string containing all possible characters for passphrase generation.
        - `_MAX_KEYLENGTH`: int: The maximum length for cryptographic keys (32).
        - `_MAX_TOKENS`: int: Maximum number of tokens for cryptographic operations (default: 100,000).
        - `_MAX_CAPACITY`: int: = Maximumum number of characters to be generated. (For personal use only when using flexible `_generate_key` method.)
        - `_EXECUTOR`: ThreadPoolExecutor: Base executor for all engine classes.
    
    #### Important Notes:
        - Attributes `include_all_chars` and `exclude_chars` are more customizable features \
            using `System.Random` when generating Fernet keys compared to:
        
        >>> Fernet.generate_key() # Returns a string of bytes of only containing digits and ascii_letters
        
    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    """
    return CipherEngine(**kwargs).encrypt_file()


def decrypt_file(**kwargs):
    """
    #### Attributes:
        - `ciphertuple` (NamedTuple): The tuple generated from any encryption process to be used for decryption.
        - `passkey_file`: str | Path: The path to the file containing the encryption details.

    #### Returns:
        - NamedTuple: Tuple containing information about the decryption process.
    """
    return DecipherEngine(**kwargs).decrypt_file()


def encrypt_text(**kwargs):
    encrypt_text.__doc__ = encrypt_file.__doc__
    return CipherEngine(**kwargs).encrypt_text()


def decrypt_text(**kwargs):
    decrypt_text.__doc__ = decrypt_file.__doc__
    return DecipherEngine(**kwargs).decrypt_text()


__version__ = "0.3.0"
__author__ = "Yousef Abuzahrieh <yousef.zahrieh17@gmail.com"
__all__ = (
    "encrypt_file",
    "decrypt_file",
    "encrypt_text",
    "decrypt_text",
    "CipherEngine",
    "DecipherEngine",
    "CipherException",
    "generate_crypto_key",
)

# XXX Markdown Files
if all(
    map(
        lambda fp: Path(fp).is_file(),
        (
            readme_str := "README.md",
            changelog_str := "CHANGELOG.md",
            cli_str := "CLI-OPTIONS.md",
        ),
    )
):
    _open = partial(open, mode="r", encoding="utf-8", errors="ignore")
    __doc__ = _open(readme_str).read()
    changelog = _open(changelog_str).read()
    source_code = _open(__file__).read()
    cli_options = _open(cli_str).read()


if __name__ == "__main__":
    arg_parser = ArgumentParser(
        description="Command-line interface designed for the management of cryptographic keys, \
            along with the capabilities for encrypting/decrypting both text and files."
    )

    # XXX Main Subparser
    subparsers = arg_parser.add_subparsers(dest="command", help="All Command Options.")

    # XXX Main Options (documentation, changelog and source code)
    arg_parser.add_argument(
        "-s", "--source", action="store_true", help="Display source code."
    )
    arg_parser.add_argument(
        "-d", "--doc", action="store_true", help="Display documentation."
    )
    arg_parser.add_argument(
        "-c", "--change-log", action="store_true", help="Display change-log."
    )

    # XXX Generate a Cryptographic Key
    generate_key_parser = subparsers.add_parser(
        "generate_key", help="Generate a secure cryptographic key."
    )
    generate_key_parser.add_argument(
        "--gd",
        action="store_true",
        help="Display documentation.",
    )
    generate_key_parser.add_argument(
        "-l", "--length", type=int, help="Specify the length of the cryptographic key."
    )
    generate_key_parser.add_argument(
        "-a",
        "--all-chars",
        action="store_true",
        help="Include all available characters in the cryptographic key.",
    )
    generate_key_parser.add_argument(
        "-b",
        "--bypass-length",
        action="store_true",
        help="Bypass restrictions for cryptographic key length.",
    )
    generate_key_parser.add_argument(
        "-s",
        "--repeat",
        type=int,
        help="Specify the repeat count for characters to be cycled through (Not needed).",
    )
    generate_key_parser.add_argument(
        "-e",
        "--exclude-chars",
        type=str,
        help="Specify characters to exclude from the cryptographic key.",
    )

    generate_key_parser.add_argument(
        "-se",
        "--safe-encoding",
        type=str,
        help="Applies URL-safe Base64 encoding to the passkey",
    )

    # XXX Encrypt Text with all paramters
    encrypt_text_parser = subparsers.add_parser(
        "encrypt_text", help="Encrypt any text with customizable parameters"
    )
    encrypt_text_parser.add_argument("-t", "--text", help="The text to be encrypted.")
    encrypt_text_parser.add_argument(
        "-n",
        "--num-keys",
        help="The number of cryptographic keys to be generated and processed with for encryption.",
    )
    encrypt_text_parser.add_argument(
        "-ec",
        "--exclude-chars",
        help="Characters to exclude during passphrase generation",
    )
    encrypt_text_parser.add_argument(
        "--all-chars",
        action="store_true",
        help="Include all available characters in the cryptographic key.",
    )
    encrypt_text_parser.add_argument(
        "-fn",
        "--file-name",
        help="The name of the file containing the encryption details.",
    )
    encrypt_text_parser.add_argument(
        "-s",
        "--serializer",
        help="The type of serialization to be used for exporting the passkey file.",
    )
    encrypt_text_parser.add_argument(
        "--special-keys",
        action="store_true",
        help="Enables CipherEngine's custom cryptographic key generation.",
    )
    encrypt_text_parser.add_argument(
        "-ep",
        "--export-path",
        help="The path for the passkey configuration file to be exported too.",
    )
    encrypt_text_parser.add_argument(
        "-i",
        "--identifiers",
        help="Specifiy a custom encryption identifier for the start and end of the encryption key",
    )
    encrypt_text_parser.add_argument(
        "--export-passkey",
        action="store_true",
        help="Exports passkey configuration file.",
    )
    encrypt_text_parser.add_argument(
        "--etd", action="store_true", help="Display documentation."
    )

    # XXX Decrypt Text with the given passkey file
    decrypt_text_parser = subparsers.add_parser(
        "decrypt_text", help="Decrypt the given text."
    )
    decrypt_text_parser.add_argument(
        "-pf", "--passkey-file", help="The path of the passkey configuration file."
    )
    decrypt_text_parser.add_argument(
        "--dtd", action="store_true", help="Display documentation."
    )

    # XXX Encrypt a File with all parameters
    encrypt_file_parser = subparsers.add_parser(
        "encrypt_file", help="Encrypt a file with customizable parameters."
    )
    encrypt_file_parser.add_argument("-f", "--file", help="The file to be encrypted.")
    encrypt_file_parser.add_argument(
        "-n",
        "--num-keys",
        help="The number of cryptographic keys to be generated and processed with for encryption.",
    )
    encrypt_file_parser.add_argument(
        "-fn",
        "--file-name",
        help="The name of the file containing the encryption details.",
    )
    encrypt_file_parser.add_argument(
        "-ec",
        "--exclude-chars",
        help="Characters to exclude during passphrase generation",
    )
    encrypt_file_parser.add_argument(
        "-ep",
        "--export-path",
        help="The path where exported files will be stored.",
    )
    encrypt_file_parser.add_argument(
        "-b", "--backup", action="store_true", help="Backup original file."
    )
    encrypt_file_parser.add_argument(
        "-o",
        "--overwrite",
        action="store_true",
        help="Overwrite the original file into an encrypted file.",
    )
    encrypt_file_parser.add_argument(
        "-e", "--export-passkey", help="Exports passkey configuration file."
    )
    encrypt_file_parser.add_argument(
        "-a",
        "--all-chars",
        help="Include all available characters in the cryptographic key.",
    )
    encrypt_file_parser.add_argument(
        "-i",
        "--identifiers",
        help="Specifiy a custom encryption identifier for the start and end of the encryption key",
    )
    encrypt_file_parser.add_argument(
        "--efd", action="store_true", help="Display documentation."
    )
    encrypt_file_parser.add_argument(
        "--special-keys",
        action="store_true",
        help="Enables CipherEngine's custom cryptographic key generation.",
    )

    # XXX Decrypt a File with given passkey file
    decrypt_file_parser = subparsers.add_parser(
        "decrypt_file", help="The file to be decrypted."
    )
    decrypt_file_parser.add_argument(
        "-pf", "--passkey-file", help="The path of the passkey configuration file."
    )
    decrypt_file_parser.add_argument(
        "-o",
        "--overwrite",
        action="store_true",
        help="Overwrite the original file into an encrypted file.",
    )
    decrypt_file_parser.add_argument(
        "--dfd", action="store_true", help="Display documentation."
    )

    args = arg_parser.parse_args()
    if not args.command:
        if not cli_options:
            for _idx, aparser in enumerate(
                (
                    arg_parser,
                    generate_key_parser,
                    encrypt_text_parser,
                    decrypt_text_parser,
                    encrypt_file_parser,
                    decrypt_file_parser,
                )
            ):
                aparser.print_help(
                    file=open(cli_str, mode="a", encoding="utf-8", errors="ignore")
                )
            print("Re-run to update CLI-OPTIONS.md file.")
            sys.exit(0)
        elif Path(cli_str).is_file() and len(cli_options) >= 1:
            print(cli_options)
            sys.exit(0)
    elif args.source:
        print(source_code)
    elif args.doc:
        print(__doc__)
    elif args.change_log:
        print(changelog)
    if args.command == "generate_key":
        if args.gd:
            print(generate_crypto_key.__doc__)
        else:
            print(
                generate_crypto_key(
                    key_length=args.length,
                    exclude=args.exclude_chars,
                    include_all_chars=args.all_chars,
                    repeat=args.repeat,
                    bypass_keylength=args.bypass_length,
                    urlsafe_encoding=args.safe_encoding,
                )
            )
    elif args.command == "encrypt_text":
        if args.etd:
            print(encrypt_text.__doc__)
        else:
            print(
                encrypt_text(
                    text=args.text,
                    file_name=args.file_name,
                    exclude_chars=args.exclude_chars,
                    num_of_keys=args.num_keys,
                    include_all_chars=args.all_chars,
                    export_passkey=args.export_passkey,
                    export_path=args.export_path,
                )
            )
    elif args.command == "decrypt_text":
        if args.dtd:
            print(decrypt_text.__doc__)
        else:
            print(decrypt_text(passkey_file=args.passkey_file))
    elif args.command == "encrypt_file":
        if args.efd:
            print(encrypt_file.__doc__)
        else:
            print(
                encrypt_file(
                    file=args.text,
                    passkey_file=args.passkey_file,
                    exclude_chars=args.exclude_chars,
                    num_of_keys=args.num_keys,
                    backup_file=args.backup,
                    include_all_chars=args.all_chars,
                    overwrite_file=args.overwrite,
                    export_passkey=args.export_passkey,
                    export_path=args.export_path,
                )
            )
    elif args.command == "decrypt_file":
        if args.dtd:
            print(decrypt_file.__doc__)
        else:
            print(
                decrypt_file(
                    passkey_file=args.passkey_file,
                    overwrite_file=args.overwrite,
                )
            )
