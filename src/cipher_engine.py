import ast
import os
import re
import sys
import math
import json
import ctypes
import base64
import hashlib
import shutil
import logging
import psutil
import secrets
import warnings
import operator
import inspect
import numpy as np
import configparser
import tkinter as tk
from tkinter import simpledialog
from pathlib import Path
from logging import Logger
from datetime import datetime
from functools import partial
from random import SystemRandom
from itertools import cycle, islice
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from collections import OrderedDict, namedtuple
from string import digits, punctuation, ascii_letters, whitespace
from typing import (Any, AnyStr, Dict,
                    Iterable, NamedTuple,
                    TypeVar, Optional, Union,
                    Literal, NoReturn, FrozenSet)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import _verify_key_size
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


__all__ = (
            'CipherEngine', 'DecipherEngine',
            'encrypt_file', 'decrypt_file',
            'encrypt_text', 'decrypt_text',
            'quick_ciphertext', 'quick_deciphertext'
        )

B = TypeVar('B', bool, None)
I = TypeVar('I', int, None)
N = TypeVar('N', NamedTuple, NoReturn)
P = TypeVar('P', Path, str)

def get_logger(*, name: str=__name__,
                level: int=logging.DEBUG,
                formatter_kwgs: dict=None,
                handler_kwgs: dict=None,
                mode: str='a',
                write_log: bool=True) -> Logger:
    
    logging.getLogger().setLevel(logging.NOTSET)
    _logger = logging.getLogger(name)
    
    if logging.getLevelName(level):
        _logger.setLevel(level=level)
    
    file_name = Path(__file__).with_suffix('.log')
    _formatter_kwgs = {**{'fmt': '[%(asctime)s][LOG %(levelname)s]:%(message)s',
                        'datefmt': '%Y-%m-%d %I:%M:%S %p'},
                       **(formatter_kwgs or {})}
    _handler_kwgs = {**{'filename': file_name, 'mode': mode},
                    **(handler_kwgs or {})}
    
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

logger = get_logger(level=logging.INFO,
                    write_log=True)

class CipherException(BaseException):
    def __init__(self, *args, log_method: logger=logger.critical):
        self.log_method = log_method
        super().__init__(*args)
        self.log_method(*args)


@dataclass_json
class JSONify(Dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    @classmethod
    def convert2strings(cls, __data):
        return JSONify(
            **{k:
            str(v) if not isinstance(v, dict)
            else cls.convert2strings(v)
            for k, v in __data.items()
            })


class _BaseSuffix(NamedTuple):
    """
    Enumeration class for common suffixes used in the CipherEngine operations.
    
    Attributes:
    - _AES: str: Suffix for AES encrypted files.
    - _DEC: str: Suffix for decrypted files.
    - _CFB: str: Suffix for Cipher Feedback (CFB) mode.
    - _INI: str: Suffix for INI configuration files.
    - _JSON: str: Suffix for JSON configuration files if _INI fails.
    - _PRE_ENC: str: Prefix for encrypted files if 'overwrite' arugment is not enabled.
    - _PRE_DEC: str: Prefix for decrypted files if 'overwrite' arugment is not enabled.
    - _MHZ: str: Suffix for MegaHertz.
    - _GHZ: str: Suffix for GigaHertz.
    """
    _AES = 'aes'
    _DEC = 'dec'
    _CFB = 'CFB8'
    _INI = 'ini'
    _JSON = 'json'
    _PRE_ENC = 'encrypted'
    _PRE_DEC = 'decrypted'
    _ALGO_TYPE = 'SHA512'
    _MHZ = 'MHz'
    _GHZ = 'GHz'


class _BasePower:
    """
    Base class providing common attributes for power-related configurations in the CipherEngine.
    
    Attributes:
    - _POWER: None: Placeholder for power-related information.
    - _SPEED: None: Placeholder for speed-related information.
    - _MIN_CORES: int: Minimum number of CPU cores (default: 2).
    - _MAX_CORES: int: Maximum number of CPU cores (default: 64).
    - _MAX_TOKENS: int: Maximum number of tokens for cryptographic operations (default: 100,000).
    - _MIN_CAPACITY: int: Minimum capacity for cryptographic operations (default: 10,000).
    - _MAX_CAPACITY: int: Maximum capacity for cryptographic operations (default: 100,000,000).
    - _Suffix: _BaseSuffix: Reference to the _BaseSuffix enumeration class.
    """
    _POWER = None
    _SPEED = None
    _MIN_CORES = 2
    _MAX_CORES = 64
    _MAX_TOKENS = int(1e5)
    _MIN_CAPACITY = int(1e4)
    _MAX_CAPACITY = int(1e8)
    _Suffix = _BaseSuffix
    
    def __init__(self) -> None:
        pass
    
    @property
    def clock_speed(self) -> NamedTuple:
        clock_spd = self._SPEED
        if clock_spd is None:
            clock_spd = self._get_clock_speed()
        return clock_spd
    
    @property
    def cpu_power(self):
        cpu_power = self._POWER
        if cpu_power is None:
            cpu_power = self._get_cpu_power()
        return cpu_power
    
    def calculate_cpu(self, **kwargs):
        return self._get_cpu_power(**kwargs)
    
    @property
    def get_cpu_chart(self):
        '''CPU _Power Chart'''
        return self._get_cpu_power(return_dict=True)
    
    @classmethod
    def _get_clock_speed(cls) -> N:
        Speed = namedtuple('ClockSpeed', ('speed', 'unit'))
        frequencies = psutil.cpu_freq(percpu=False)
        if frequencies:
            mega, giga = cls._Suffix._MHZ, cls._Suffix._GHZ
            clock_speed = frequencies.max / 1000
            unit = giga if clock_speed >= 1 else mega
            return Speed(clock_speed, unit)
        raise CipherException(
            'Unable to retrieve CPU frequency information to determine systems clock speed.'
            )
    
    @classmethod
    def _sig_larger(cls, *args) -> N:
        """
        Calculate the significant difference between two numerical values.

        Parameters:
        - args (Tuple): Two numerical values for comparison.

        Returns:
        - NamedTuple: A named tuple with two fields:
            - status (bool): True if the absolute difference is within the threshold, False otherwise.
            - threshold (float): The adjusted threshold value.

        Raises:
        - CipherException: If excessive arguments are provided; requires precisely two numerical values.

        Note:
        The 'status' field indicates whether the absolute difference between the provided values
        is within the threshold (1e5). If 'status' is False, the 'threshold' field will be the maximum
        of the provided values and the threshold.
        """
        
        valid_args = all(
                    (map(partial(_BaseEngine._validate_object, arg='Key Length'), 
                        args)
                    ))
        
        if len(args) == 2 and valid_args:
            threshold = cls._MAX_TOKENS
            Sig = namedtuple('SigLarger', ('status', 'threshold'))
            abs_diff = abs(operator.sub(*args))
            status = operator.le(*map(math.log1p, (abs_diff, threshold)))
            return Sig(status, max(max(args), threshold))
        raise CipherException(
            'Excessive arguments provided; requires precisely two numerical values, such as integers or floats.'
            )
    
    def _get_cpu_power(self,
                    min_power: bool=False,
                    max_power: bool=False,
                    return_dict: bool=False) -> Union[int, Dict[int, int]]:
        """
        ### Calculate and return a recommended CPU power value based on the number of CPU cores.

        #### Parameters:
            - min_power (bool): If True, considers minimum power constraints.
            - max_power (bool): If True, considers maximum power constraints.
            - return_dict (bool): If True, returns the CPU power chart as a dictionary.
        
        #### Note:
            - The calculation is based on a base power value derived from a logarithmic range.
            - The user's CPU count is used to determine the recommended power,
            with a minimum of 2 cores and a maximum of 64 cores considered.
            - This method utilizes NumPy for efficient array operations.
        
        #### Returns:
        - Union[int, Dict[int, int]]: If return_dict is True, returns the CPU power chart as a dictionary.
        Otherwise, calculates and returns the total power based on specified conditions.
        """
        
        if all((min_power, max_power)):
            max_power = False
        base_power_range = np.logspace(
                            np.log10(self.min_cores),
                            np.log10(self._MIN_CAPACITY),
                            1000, self._MAX_CAPACITY).astype('float64')
        base_power = base_power_range[self.max_cores + 1] * self._MIN_CAPACITY
        cpu_counts = np.arange(self.min_cores, self.max_cores + 1)
        cpu_powers = np.multiply(base_power, cpu_counts, order='C', subok=True).astype('int64')
        cpu_chart = OrderedDict(zip(cpu_counts, cpu_powers))
        if return_dict:
            return cpu_chart
        
        try:
            total_power = cpu_chart[self.min_cores + 
                                min((self.min_cores % 10, self.max_cores % 10))]
        except KeyError:
            total_power = next(iter(cpu_chart.values()))
        
        first_or_last = lambda _x: next(iter(_x[slice(-1, None, None)]))
        
        if any((min_power,
                total_power >= self._MAX_CAPACITY,
                self.clock_speed.unit==self._Suffix._MHZ)):
            total_power = first_or_last(cpu_chart.popitem(last=False))
        
        if max_power:
            if self.clock_speed.unit==self._Suffix._GHZ:
                total_power =  first_or_last(cpu_chart.popitem())
            CipherException(
                "CAUTION: The 'max_power' parameter is designed for determining the maximum number "
                " of iterations to be utilized in the algorithm encryption/decryption process, subject to meeting the computational prerequisites. "
                f"\nHence, specific computational prerequisites must be fulfilled beforehand. Defaulting to {total_power}"
                )
        
        return total_power
    
    @classmethod
    def _capacity_error(cls, *args) -> NoReturn:
        raise CipherException(
            f"The specified counts surpasses the computational capacity required for {cls.__name__!r}. "
            " It is recommended to use a count of 100 <= x <= 1000, considering the specified 'key_length'. "
            f' {(*args,)}')
    
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


class _ConfigParser(configparser.ConfigParser):
    def __init__(self, *args, dict_type=dict, allow_no_value=True, **kwargs):
        _kwargs = {
                    'dict_type': dict_type,
                    'allow_no_value': allow_no_value,
                    'converters': {'*': self.convert_value},
                    **kwargs
                }
        super().__init__(*args, **_kwargs)
    
    def get(self, section, option, *, raw=False, vars=None, fallback=None):
        value = super().get(section, option, raw=raw, vars=vars, fallback=fallback)
        return self.convert_value(value)
    
    def convert_value(self, value: Any):
        str_val = str(value).lower()
        val_mapper = {'true': True, 'false': False, 'none': None}
        return val_mapper.get(str_val, value)


@dataclass(kw_only=True)
class _BaseEngine(_BasePower):
    """
    Base class for the CipherEngine hierarchy, providing common attributes and functionality for encryption.
    
    Attributes:
    - file: Path | None: The path to the file to be processed (default: None).
    - file_name: str | None: The name of the file containing the encryption details.
    - text: str | None: The text data to be processed (default: None).
    - passkey_file: Path | None: The path to the file containing the encryption details (default: None).
    - export_path: Path | None: The path where exported files will be stored (default: None).
    - verbose: bool: Flag indicating whether to print verbose messages (default: False).
    - overwrite_file: bool: Flag indicating whether to overwrite the original file during processing (default: False).
    - hash_type (str): The algorithm to be utilized for the encryption process, which will correspond to its respective Cipher algorithm by default (PBKDF2 default: SHA512).
    - algorithm_type (str): The type of encryption algorithm to be used (default: 'AES').
        - Note: The algorithm type must correspond to the hash type block sizes,
            or it will attempt to find the right match instead of raising an error.
    - ciphertuple (NamedTuple): The tuple generated from any encryption process to be used for decryption.
    
    Class Attributes:
    - _BACKEND: cryptography.hazmat.backends.Backend: The cryptography backend used for cryptographic operations.
    - _ALL_CHARS: str: A string containing all possible characters for passphrase generation.
    - _MIN_KEYLENGTH: int: The minimum length for cryptographic keys (default: 32).
    - _MIN_PBKLEN: int: The minimum length for key derivation using PBKDF2 (default: 32).
    - _MAX_KEYLENGTH: int: The maximum length for cryptographic keys, derived from the _BasePower class.
    
    """
    file: Optional[P] = field(repr=False, default=None)
    file_name: str = field(repr=False, default=None)
    text: Optional[P] = field(repr=False, default=None)
    ciphertuple: NamedTuple = field(repr=False, default=None)
    passkey_file: Optional[P] = field(repr=False, default=None)
    export_path: Optional[P] = field(repr=False, default=None)
    verbose: Optional[B] = field(repr=False, default=False)
    overwrite_file: Optional[B] = field(repr=False, default=False)
    
    _BACKEND = default_backend()
    _ALL_CHARS = (digits + punctuation + ascii_letters)
    _MIN_KEYLENGTH = 32
    _MAX_KEYLENGTH = _BasePower._MAX_CAPACITY
    _DEPRECATED_ALGOS = ('Blowfish', 'CAST5', 'IDEA', 'SEED')
    
    @property
    def _identifier(self):
        return '-----BEGIN CIPHERENGINE AES ENCRYPTED KEY-----'.encode()
    
    @staticmethod
    def _new_parser():
        return _ConfigParser()
    
    def _log_verbose(self, __msg: str, lg_method: logger=logger.info):
        if self.verbose:
            CipherException(__msg, log_method=lg_method)
    
    @classmethod
    def _new_fernet(cls, __key: bytes | str) -> Fernet:
        try:
            new_fernet = Fernet(__key, backend=cls._BACKEND)
        except ValueError:
            key = cls._base64_key(__key.encode())
            return cls._new_fernet(key)
        return new_fernet
    
    @classmethod
    def _failed_hash(cls, org_hash: bytes, second_hash: bytes) -> CipherException:
        raise CipherException(
            'The discrepancy in hashed values points to a critical integrity issue, suggesting potential data loss. '
            'Immediate data investigation and remedial action are strongly advised. '
            f'\nOriginal Hash: {org_hash}'
            f'\nDecrypted Hash: {second_hash}'
        )
    
    @classmethod
    def _base_power(cls):
        return cls().cpu_power
    
    def _print_header(self, __name: str='',
                            encrypting: bool=True,
                            with_iterations: bool=True,
                            activated: bool=True) -> str:
        """
        Prints the main header for activating/deactivating the tool.
        
        Args:
            - name (Optional[str]): The name to display in the header. If None, the class name in uppercase is used.
            - encrypting (bool): If True, indicates encryption; otherwise, decryption.
            - with_iterations (bool): If True, includes the number of iterations in the header.
            - activated (bool): If True, the tool is activated in green; otherwise, deactivated.
        """
        if callable(self):
            cls_name = self.__name__
        else:
            cls_name = self.__class__.__name__
        
        repr_name = self._validate_object(__name, type_is=str) or cls_name
        term_size = self._terminal_size()
        iterations = self._iterations if hasattr(self, '_iterations') \
                    and isinstance(self._iterations, int) \
                    else self._base_power()
        
        if self.verbose:
            iter_str = f' (iterations={iterations:_})'
            header = '{} {} Tool {}{}'.format(
                                    repr_name,
                                    'decryption' if not encrypting else 'encryption',
                                    'activated' if activated else 'de-activated',
                                    iter_str if with_iterations else '').upper()
            #** 31: Red, 32: Green
            color_code = '31' if not activated else '32'
            print(
            '\033[1;{}m{}\033[0m'.format(color_code, header.center(term_size, '*'), flush=True)
            )
    
    @staticmethod
    def _template_parameters() -> FrozenSet:
        return frozenset(
                {'iterations', 'hash_value', 'salt_value',
                'hash_type', 'algorithm_type',
                'iv_value', 'encrypted_text', 'encrypted_file',
                'decipher_key', 'original_text', 'original_file'}
        )
    
    def _new_template(self, **kwargs) -> Dict:
        '''
        #### \
        This method creates a dynamic template incorporating encryption parameters and security details \
        suitable for writing encrypted data to a file. \
        The generated template can later be employed in the decryption process.
        '''
        #XXX SECURITY_PARAMS
        hash_val = kwargs.pop(hash_str:=('hash_value'), None)
        iterations = kwargs.pop(iter_str:=('iterations'), self.cpu_power)
        salt_val = kwargs.pop(salt_str:=('salt_value'), None)
        iv_val = kwargs.pop(iv_str:=('iv_value'), None)
        algorithm = kwargs.pop(algo_str:=('algorithm_type'), algorithms.AES)
        hash_type = kwargs.pop(h_str:=('hash_type'), hashes.SHA512)
        salt_iv = {salt_str: salt_val, iv_str: iv_val} \
                if all((salt_val, iv_val)) else {}
        
        return {'CIPHER_INFO': {**kwargs},
                'SECURITY_PARAMS':
                    {iter_str: iterations,
                    h_str: hash_type,
                    algo_str: algorithm,
                    'mode': self._Suffix._CFB,
                    hash_str: hash_val,
                    **salt_iv
                    }
                }
    
    @staticmethod
    def _format_file(__file: P) -> str:
        time_now = datetime.now()
        formatted_time = time_now.strftime('%Y-%m-%dT%I-%M-%S%p-')
        return (__file.parent / formatted_time).as_posix() + (f'backup-{__file.name}')
    
    @staticmethod
    def _bytes_read(__file: P) -> bytes:
        with open(__file, mode='rb') as _file:
            _text = _file.read()
        return _text
    
    @classmethod
    def _create_subclass(cls,
                        typename: str='FieldTuple',
                        /,
                        field_names: Iterable=None,
                        *,
                        rename: bool=False,
                        module: str=None,
                        defaults: Iterable=None,
                        values: Iterable=None,
                        num_attrs: int=5,
                        field_doc: str='Tuple containing dependecies for decryption purposes.'
                        ) -> NamedTuple:
        """
        Create a dynamically generated namedtuple subclass.
        
        Parameters:
        - typename (str): Name of the named tuple subclass.
        - field_names (List[str]): List of field names.
        - rename (bool): Whether to rename invalid field names.
        - module (str): Module name for the namedtuple subclass.
        - defaults (Tuple): Default values for fields.
        - num_attrs (int): Number of default attributes if field_names is not provided.
        - num_attrs (int): The number of default attributes assigned to the object when no specific field names are provided.
        - field_doc (str): List of documentation strings for each field.
        
        Returns:
        - Named tuple subclass.
        """
        
        if not isinstance(num_attrs, int) or num_attrs <= 0:
            raise CipherException(f"{num_attrs!r} is not a positive integer.")
        
        _field_names = field_names or np.core.defchararray.add('attr', np.arange(1, num_attrs+1).astype(str))
        default_vals = defaults or (None,) * len(_field_names)
        field_docs = field_doc or ''
        module_name = module or 'CipherTuple'
        new_tuple = namedtuple(typename=typename,
                                field_names=_field_names,
                                rename=rename,
                                defaults=default_vals,
                                module=module_name)
        setattr(new_tuple, '__doc__', field_docs)
        if values:
            return new_tuple(*values)
        return new_tuple
    
    @staticmethod
    def _validate_file(__file: P) -> Path:
        try:
            _file = Path(__file)
        except TypeError as t_error:
            raise CipherException(t_error)
        
        if not _file:
            raise CipherException(f"File arugment must not be empty: {_file!r}")
        elif not _file.exists():
            raise CipherException(f"File does not exist: {_file!r}. Please check system files.")
        elif all((not _file.is_file(), not _file.is_absolute())):
            raise CipherException(f"Invalid path type: {_file!r}. Path must be a file type.")
        elif _file.is_dir():
            raise CipherException(f"File is a directory: {_file!r}. Argument must be a valid file.")
        return _file
    
    @staticmethod
    def _terminal_size() -> int:
        return shutil.get_terminal_size().columns
    
    @classmethod
    def _filter_chars(cls, __string: str, *, exclude: str='') -> str:
        """
        Filter characters in the given string, excluding those specified.
        
        Parameters:
        - __string (str): The input string to be filtered.
        - exclude (str): Characters to be excluded from the filtering process.
        
        Returns:
        - str: The filtered string with specified characters excluded.
        
        Notes:
        - This method employs the `translate` method to efficiently filter characters.
        - Whitespace, form feed (\f), and vertical tab (\v) are automatically excluded.
        - To exclude additional characters, provide them as a string in the `exclude` parameter.
        
        """
        check_str = cls._validate_object(__string, type_is=str)
        full_string = ''.join(check_str)
        filter_out = ("\f\v" + whitespace + exclude)
        string_filtered = full_string.translate(str.maketrans('', '', filter_out))
        return string_filtered
    
    @staticmethod
    def _find_mem_loc(__obj: object) -> str:
        """
        Returns the memory location of the given object in hexadecimal format.

        Args:
        __obj (object): The object whose memory location is to be found.

        Returns:
        str: The memory location of the object as a hexadecimal string.

        Example:
        >>> _find_mem_loc("hello")
        '0x7f8f3c0a5f70'
        """
        try:
            buffer = memoryview(bytearray(__obj))
            address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        except (MemoryError, ValueError):
            raise 
        return hex(address)
    
    @staticmethod
    def _exclude_type(__key: str='punct', return_dict: bool=False) -> str:
        """
        ### Exclude specific character sets based on the provided key.

        #### Parameters:
        - __key (str): The key to select the character set to exclude.
        - return_dict (bool): If True, returns the dicitonary containing all possible exluce types.

        #### Returns:
        - str: The selected character set based on the key to be excluded from the generated passkey.

        #### Possible values for __key:
        >>> 'digits': Includes digits (0-9).
        >>> 'punct': Includes punctuation characters.
        >>> 'ascii': Includes ASCII letters (both uppercase and lowercase).
        >>> 'digits_punct': Includes both digits and punctuation characters.
        >>> 'ascii_punct': Includes both ASCII letters and punctuation characters.
        >>> 'digits_ascii': Includes both digits and ASCII letters.
        """
        all_chars = {
                    'digits': digits,
                    'punct': punctuation,
                    'ascii': ascii_letters,
                    'digits_punct': digits + punctuation,
                    'ascii_punct': ascii_letters + punctuation,
                    'digits_ascii': digits + ascii_letters
                    }
        if return_dict:
            return all_chars
        return all_chars.get(__key)
    
    @staticmethod
    def _base64_key(__key: str):
        try:
            return base64.urlsafe_b64encode(__key)
        except AttributeError as attr_error:
            raise CipherException(
                f'Failed to derive encoded bytes from {__key!r}. '
                f'\n{attr_error}'
            )
    
    @staticmethod
    def _calc_file_hash(__file: P) -> str:
        """
        Calculate the SHA-256 hash of the content in the specified file.
        
        Parameters:
        - file_path (str): The path to the file for which the hash is to be calculated.
        
        Returns:
        - str: The SHA-256 hash value as a hexadecimal string.
        """
        sha256_hash = hashlib.sha256()
        with open(__file, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    @classmethod
    def _calc_str_hash(cls, __text: str):
        """
        Calculate the SHA-256 hash of the provided text.
        
        Parameters:
        - text (str): The input text for which the hash is to be calculated.
        
        Returns:
        - str: The SHA-256 hash value as a hexadecimal string.
        """
        valid_text = cls._validate_object(__text, type_is=str).encode()
        hash_ = hashlib.sha256()
        hash_.update(valid_text)
        return hash_.hexdigest()
    
    @staticmethod
    def _validate_object(__obj: Any, type_is: type=int, arg: str='Argument') -> (int | str | list[str] | Path | Literal[False]):
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
        CEerror = CipherException
        possible_instances = (TypeError, ValueError, SyntaxError)
        
        if type_is is Any:
            type_is = type(__obj)
        
        if type_is in (int, float):
            try:
                _obj = int(ast.literal_eval(str(__obj)))
            except possible_instances:
                raise CEerror(f'{arg!r} must be of type {int} or integer-like {str}')
        elif type_is is str:
            try:
                _obj = str(__obj)
            except possible_instances:
                raise CEerror(f'{arg!r} must be of type {str}')
        elif type_is is list:
            try:
                _obj = list(map(str, __obj))
            except possible_instances:
                raise CEerror(f'{arg!r} must be of type {list} with {int} or integer-like {str}')
        elif type_is is Path:
            try:
                _obj = Path(__obj)
            except possible_instances:
                raise  CEerror(f'{arg!r} must be of type {Path} or {str}')
        else:
            return False
        
        return _obj
    
    @classmethod
    def _generate_key(cls, *,
                    key_length: int=32,
                    exclude: str='',
                    include_all_chars: bool=False,
                    bypass_length_limit: bool=False,
                    repeat: int=None) -> str:
        
        if all((exclude, include_all_chars)):
            raise CipherException(
                "Cannot specify both 'exclude' and 'include_all_chars' arguments."
                )
        
        if repeat:
            repeat_val = cls._validate_object(repeat, type_is=int, arg='repeat')
        else:
            repeat_val = cls._MAX_CORES
        
        if repeat_val >= cls._MAX_CAPACITY:
            cls._capacity_error(f'Max Tokens: {cls._MAX_TOKENS}',
                                f'Character Repeat Count: {repeat_val}')
        
        key_len = cls._validate_object(key_length, type_is=int, arg='key_length')
        threshold = cls._sig_larger(key_len, int(repeat_val))
        
        if not bypass_length_limit and \
            any((key_len < cls._MIN_KEYLENGTH,
                key_len > cls._MAX_KEYLENGTH)):
            raise CipherException(
                f'\'key_length\' must be of value {cls._MIN_KEYLENGTH} <= x <= {cls._MAX_KEYLENGTH:_}.'
                )
        
        if not threshold.status:
            cls._MAX_TOKENS = threshold.threshold
            CipherException(
                "The specified values for 'key_length' or 'iterations' exceeds the number of characters that can be cycled during repetition."
                f" Higher values for 'max_tokens' count is recommended for better results ('max_tokens' count is now {cls._MAX_TOKENS}).",
                log_method=logger.warning
                )
        
        slicer = lambda *args: ''.join(islice(*args, cls._MAX_TOKENS))
        all_chars = slicer(cycle(cls._ALL_CHARS))
        filtered_chars = cls._filter_chars(all_chars, exclude=punctuation)
        
        if include_all_chars:
            filtered_chars = all_chars
        
        if exclude:
            _exclude = cls._validate_object(exclude, type_is=str, arg='exlcude')
            exclude_type = cls._exclude_type(_exclude)
            filtered_chars = filtered_chars if not exclude_type \
                            else cls._filter_chars(all_chars, exclude=exclude_type)
        
        passkey = SystemRandom().sample(
                        population=filtered_chars,
                        k=min(key_len, len(filtered_chars))
                        )
        return ''.join(passkey)
    
    @classmethod
    def _parse_config(cls, __config: P, *, section: str='SECURITY_PARAMS', section_key: str) -> Union[str, Any]:
        file_suffix = __config.suffix.lstrip('.')
        try:
            if file_suffix==cls._Suffix._JSON:
                cparser = json.loads(open(__config).read())
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
            raise CipherException(
                    f"An unexpected error occurred while attempting to read the configuration file {__config.name}. "
                    f"The decryption algorithm is designed to work with its original values. "
                    "Please note that if the passphrase contains special characters, it may result in decryption issues."
                    )
        return sec_val
    
    @staticmethod
    def _gen_random(__size: int=16) -> bytes:
        return secrets.token_bytes(__size)
    
    @classmethod
    def _get_object_classes(cls, __obj: object):
        """
        Retrieve all classes defined in the specified object, excluding deprecated algorithms.

        Parameters:
        - __obj (object): The object to inspect.

        Returns:
        - List[Type[CipherAlgorithm]]: A list of class types found in the object.

        Example:
        >>> classes = YourClass._get_object_classes(YourModule)

        Note:
        - This method utilizes the inspect module to gather all classes defined in the provided object,
        excluding those flagged as deprecated according to the CipherEngine deprecation standards.
        """
        return [algo[0] for algo in inspect.getmembers(__obj, inspect.isclass)
                if not cls._compiler(cls._DEPRECATED_ALGOS, algo[0], escape_k=False)]
    
    @classmethod
    def _validate_algorithm_type(cls, __obj: object, __type: str):
        """
        Validates the specified algorithm type for PBKDF2 (hashes) and Cipher (algorithms) algorithms.
        
        Parameters:
            algorithm_object (object): An object containing the algorithm type.
            algorithm_type (str): The name of the attribute representing the algorithm type.
        
        Returns:
            object: An instance of the specified algorithm type.
        
        Raises:
            AttributeError: If the specified attribute representing the algorithm type does not exist.
        """
        all_algorithms = cls._get_object_classes(__obj)
        a_type = cls._compiler(all_algorithms, __type, escape_k=False)
        if a_type:
            try:
                cls._check_deprecation(__type)
                hash_type = getattr(__obj, __type)
            except AttributeError:
                raise CipherException(
                    f'{__type} is not a valid type for {__obj.__name__!r}.'
                    )
        else:
            raise CipherException(
                f'No {__obj.__name__!r} types were found for {__type!r}'
            )
        
        return hash_type
    
    @classmethod
    def _check_deprecation(cls, __type):
        if cls._compiler(cls._DEPRECATED_ALGOS, __type, escape_k=False):
            raise CipherException(
                f'Algorithm {__type!r} has been deprecated.'
            )
        return __type
    
    @classmethod
    def _get_cipher(cls,
                    __key: bytes,
                    __iv: bytes=None,
                    hash_type: str=None,
                    algorithm_type: str=None) -> Cipher:
        if __iv is None:
            __iv = cls._gen_random()
        
        cipher_func = partial(Cipher,
                        mode=modes.CFB8(__iv),
                        backend=cls._BACKEND)
        
        default_atype = algorithms.AES
        default_htype = hashes.SHA384
        
        #XXX Check if specified hash and algorithm types are valid based on given key
        try:
            return cipher_func(algorithm=default_atype(__key))
        except ValueError:
            pbk2_size = getattr(hashes, default_htype).block_size
            all_algos = cls._get_object_classes(algorithms)
            algo_vals = {algo_name:
                        getattr(algorithms, algo_name).key_sizes
                        for algo_name in all_algos}
            
            try:
                # Validate that the specified algorith_type corresponds to the correct Cipher algorithm.
                _verify_key_size(default_atype, __key)
            except ValueError:
                # If not, determine the correct algorithm type based on key sizes.
                default_type = next((algo_n for algo_n, sizes in algo_vals.items() if pbk2_size in sizes))
                CipherException(
                            f'{algorithm_type} cannot be used for the specified algorithm type. ',
                            f'Found the correct {Cipher.__name__} algorithm type: ({default_type!r})',
                            log_method=logger.warning)
            return cls._get_cipher(
                    __key, __iv,
                    hash_type=default_htype,
                    algorithm_type=default_atype
                    )
    
    @classmethod
    def _get_pbk(cls,
                    __salt: bytes=None,
                    iterations: int=None,
                    hash_type: str=None
                ) -> PBKDF2HMAC:
        
        if __salt is None:
            __salt = cls._gen_random()
        
        if not hash_type:
            default_htype = hashes.SHA512
        else:
            hash_t = hash_type.__name__ if hasattr(hash_type, '__name__') else hash_type
            default_htype = cls._validate_algorithm_type(hashes, hash_t)
        
        return PBKDF2HMAC(
                algorithm=default_htype(),
                length=32,
                salt=__salt,
                iterations=iterations,
                backend=cls._BACKEND
            )
    
    @classmethod
    def _char_checker(cls, __text: str) -> bool:
        """
        Check the validity of the given __text.

        Parameters:
        - __text (str): The __text to be validated.

        Returns:
        - bool: True if all characters in the passkey are present in the predefined set;
                False otherwise.

        Example:
        >>> MyClass._char_checker("abc123")
        True

        Note:
        - This method validates whether all characters in the given passkey are part of
        the predefined set of valid characters in the class.
        """
        text = cls._validate_object(__text, type_is=str, arg='Text')
        if text:
            return all(char in cls._ALL_CHARS for char in text)
        return False
    
    @classmethod
    def _validate_ciphertuple(cls, __ctuple: NamedTuple) -> N:
        """
        Validate the structure of the NamedTuple representing cipher details.
        
        Parameters:
        - __ctuple (NamedTuple): The NamedTuple representing cipher details.
        
        Returns:
        - Set: A set containing the intersection of predefined security parameters
        and the attributes present in the given cipher tuple.
        
        Raises:
        - CipherException: If the provided tuple does not meet the expected structure.
        
        Example:
        >>> MyClass._validate_ciphertuple(cipher_tuple_instance)
        {'iterations', 'hash_value', 'salt_value', 'iv_value',
        'encrypted_text', 'decipher_key', 'original_text'}
        
        Note:
        - This method checks whether the structure of the provided NamedTuple matches the
        expected structure for cipher details.
        """
        all_parameters = cls._template_parameters()
        
        #** isinstance(__obj, NamedTuple)?
        if all((isinstance(__ctuple, tuple),
                hasattr(__ctuple, '_fields'),
                isinstance(__ctuple._fields, tuple),
                hasattr(__ctuple, '__module__'),
                getattr(__ctuple, '__module__')=='CipherTuple')):
            
            ctuple_set = set(__ctuple._asdict())
            ctuple_paramters = all_parameters & ctuple_set
            try:
                for param in ctuple_paramters:
                    param_attr = getattr(__ctuple, param)
                    str_attr = cls._validate_object(param_attr, type_is=str, arg='CipherTuple')
                    #! Ensure attribute is not null.
                    if any((not str_attr,
                            not len(str_attr)>=1)):
                        raise CipherException(
                            f'>>{str_attr} is not a valid attribute value. ',
                            '>>Ensure that all predefined configuration CipherTuples have non-null values.'
                        )
            except AttributeError as attr_error:
                raise CipherException(
                    f'>>Validation Failed: The following attribute is not predefined. ',
                    f'>>Ensure that the specified configuration {NamedTuple.__name__!r} is generated from one of the {CipherEngine.__name__!r} encryption processes. ',
                    f'>>ERROR: {attr_error}')
        
        else:
            raise CipherException(
                'Invalid NamedTuple Structure: ',
                f"{__ctuple!r} must be of type {NamedTuple.__name__!r}")
        
        return __ctuple
    
    @staticmethod
    def _create_backup(__file: P) -> None:
        CEinfo = partial(CipherException, log_method=logger.info)
        backup_path = __file.parent / f'backup/{__file.name}'
        formatted_bkp = _BaseEngine._format_file(backup_path)
        if not backup_path.parent.is_dir():
            CEinfo(
                'No backup folder detected. '
                f'Creating a backup folder named {backup_path.parent!r} to store original files securely.'
                )
            backup_path.parent.mkdir()
        
        if not backup_path.is_file():
            CEinfo(
            f'Backing up {backup_path.name} to the newly-created backup folder.',
            )
            shutil.copy2(__file, formatted_bkp)
    
    @classmethod
    def _log_separator(cls, __section: str):
        section_name = f'log-{__section}-section'.upper()
        width = max(len(section_name), cls._terminal_size())
        log_separator = section_name.center(width, '=')
        CipherException(log_separator,
                        log_method=logger.debug)
    
    @staticmethod
    def _write2file(__file: P,
                    *,
                    suffix: bool='ini', data:AnyStr='',
                    mode: str='w', parser: configparser=None,
                    reason: str='', verbose: bool=False) -> None:
        
        CEinfo = partial(CipherException, log_method=logger.info)
        new_file = Path(__file).with_suffix(f'.{suffix}')
        with open(new_file, mode=mode) as _file:
            if parser:
                parser.write(_file)
            else:
                _file.write(data)
            p_string = partial('{file!r} has successfully been {reason} to {path!r}'.format,
                            file=_file.name, path=new_file.absolute())
            if verbose:
                CEinfo(p_string(reason=reason or 'written'))
        return 
    
    @classmethod
    def _compiler(cls, __defaults, __k, escape_k=True, search=True) -> str:
        """
        Validate if the given input matches the provided defaults.

        Args:
            __defaults: Default values to match against (may contain regex patterns).
            __k: Input to validate.
            escape_k: Whether to escape special characters in the input (default is True).
            search: If True, perform a search; if False, perform a match (default is True).

        Returns:
            bool: True if the input matches any default, False otherwise.
        """
        valid_instances = (int, str, bool, bytes, Iterable)
        if any((not __k,
                not isinstance(__k, valid_instances),
                hasattr(__k, '__str__'))):
            esc_k = str(__k)
        else:
            esc_k = cls._validate_object(__k, type_is=str, arg=__k)
        
        defaults = map(re.escape, map(str, __defaults))
        pattern = '|'.join(defaults)
        if escape_k:
            esc_k = '|'.join(map(re.escape, __k))
        
        compiler = re.compile(pattern, re.IGNORECASE)
        if not search:
            compiled = compiler.match(esc_k)
        else:
            compiled = compiler.search(esc_k)
        return compiled


@dataclass(kw_only=True)
class CipherEngine(_BaseEngine):
    """
    CipherEngine class for encrypting files and text data using symmetric key cryptography.

    #### Attributes:
    - passkey: Optional[Union[str, int]]: The passphrase or key for used for encryption.
    - key_length: Optional[int]: The length of the cryptographic decipher key (default: 32).
    - iterations: Optional[int]: The number of iterations for key derivation.
    - exclude_chars: Union[list, str]: Characters to exclude during passphrase generation (default: None).
    - backup_file: bool: Flag indicating whether to create a backup of the original file (default: True).
    - export_passkey: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
    - include_all_chars: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
    - min_power: bool: Flag indicating whether to use the minimum power for key derivation (default: False).
    - max_power: bool: Flag indicating whether to use the maximum power for key derivation (default: False).
    - serializer: str: The type of serialization to be used for exporting the passkey file ('json' or 'ini').
    
    #### Methods:
    - encrypt_file(): Encrypts a specified file.
    - encrypt_text(): Encrypts a specified text.
    - quick_encrypt(): Quickly encrypts text data and exports necessary information on-the-go.

    #### Example:
    >>> cipher = CipherEngine(passkey='my_secret_key', iterations=1000)
    >>> cipher.encrypt_file()
    """
    __slots__ = ('__weakrefs__', '_iterations',
                'file', '_file', 'text', 'passkey_file',
                'export_path', 'verbose', 'overwrite_file')
    
    passkey: Optional[Union[str, int]] = field(init=True, repr=False, default=None)
    key_length: Optional[I] = field(repr=True, default=_BaseEngine._MIN_KEYLENGTH)
    iterations: Optional[I] = field(repr=True, default=None)
    exclude_chars: str = field(repr=True, default=None)
    backup_file: Optional[B] = field(repr=False, default=True)
    export_passkey: Optional[B] = field(repr=False, default=True)
    include_all_chars: Optional[B] = field(repr=False, default=False)
    min_power: Optional[B] = field(repr=False, default=False)
    max_power: Optional[B] = field(repr=False, default=False)
    hash_type: str = field(repr=False, default=None)
    algorithm_type: str = field(repr=False, default=None)
    serializer: str = field(repr=False, default=None)
    gui_passphrase: bool = field(repr=False, default=False)
    bypass_keylength: bool = field(repr=False, default=False)
    
    def __post_init__(self):
        """
        Perform post-initialization tasks including validating and deriving encryption parameters.
        """
        super().__init__(file=self.file,
                        file_name=self.file_name,
                        overwrite_file=self.overwrite_file,
                        verbose=self.verbose,
                        export_path=self.export_path,
                        
                        text=self.text)
        self._file = None if not self.file else self._validate_file(self.file)
        self._iterations = self._calculate_iterations()
        self._jserializer = self._json_serializer()
        self._hash_type, self._algorithm_type = self._validate_hash_algo()
        
        if self.gui_passphrase:
            self._passkey = self._gui_passphrase()
        else:
            self._passkey = self._validate_passkey(
                                self.passkey,
                                key_length=self.key_length,
                                exclude=self.exclude_chars,
                                include_all_chars=self.include_all_chars
                                )
    
    def _json_serializer(self):
        serializer = self._validate_object(
                            self.serializer, type_is=str, arg='Serializer'
                            )
        return self._compiler(['json'], serializer, escape_k=False)
    
    def _gui_passphrase(self):
        root = tk.Tk()
        root.withdraw()
        gui_pass = simpledialog.askstring("GUI-Passphrase", 'Enter a secure passkey:', show='*')
        passphrase = self._validate_passkey(gui_pass)
        root.destroy()
        return passphrase
        
    @classmethod
    def encryption_header(cls):
        return cls()._identifier
    
    def _validate_hash_algo(self):
        default_htype =  hashes.SHA512
        default_atype = algorithms.AES
        if self.hash_type:
            default_htype = self._validate_algorithm_type(hashes, self.hash_type)
        
        if self.algorithm_type:
            default_atype = self._validate_algorithm_type(algorithms, self.algorithm_type)
        return default_htype, default_atype
    
    @classmethod
    def exclude_chart(cls):
        return cls._exclude_type(return_dict=True)
    
    def _calculate_iterations(self) -> int:
        """
        Calculate the number of iterations for key derivation.
        
        Returns:
            - int: Number of iterations.
        """
        if self.iterations:
            iter_count = self._validate_object(self.iterations, type_is=int, arg='iterations')
            if iter_count >= self._MAX_CAPACITY:
                return self._capacity_error(f'Specified value: {iter_count}',
                                            f'Max Iterations value: {self._MAX_CAPACITY}')
            return iter_count
        
        args = (self.min_power, self.max_power)
        if any(args):
            power_info = self._create_subclass(
                                            'PStats', ('min', 'max'),
                                            values=args,
                                            module='PowerInfo',
                                            field_doc='Minimum and maximum values for number of iterations.')
            
            return self.calculate_cpu(
                            min_power=power_info.min,
                            max_power=power_info.max
                            )
        return self.cpu_power
    
    def _validate_passkey(self, __passkey: str = None, **kwargs) -> str:
        """
        Validates a given passkey. If the passkey is not provided or contains invalid characters,
        generates a new key based on the specified criteria.
        
        Parameters:
        - __passkey: str | None: The passkey to be validated.
        - **kwargs: Additional keyword arguments for key generation.
        
        Returns:
        str: Validated passkey.
        """
        
        CEwarning = partial(CipherException,
                            "For security reasons, the passkey must have a length of at least 32 characters. "
                            "If a shorter key is desired, you can provide a 'bypass_keylength' parameter. "
                            "Otherwise, the system will default to a minimum fixed key length of 32.",
                            log_method=logger.warning)
        
        def validator():
            passkey = self._validate_object(__passkey, type_is=str, arg='Passphrase')
            checker = partial(lambda *args: all((*args,)), self._char_checker(passkey))
            checked = checker(len(passkey) >= self._MIN_KEYLENGTH)
            if self.bypass_keylength and not checked:
                # No limitations. Empty strings are allowed.
                checked = checker(0 <= len(passkey) < self._MIN_KEYLENGTH)
            elif not self.bypass_keylength and not checked:
                CEwarning()
            return checked
        
        if __passkey and validator():
            return __passkey
        
        return self._generate_key(**kwargs)
    
    def _export_passkey(self, *, parser, passkey_file, data) -> None:
        passkey_suffix = self._Suffix._INI
        write_func = partial(self._write2file,
                            passkey_file,
                            verbose=self.verbose,
                            reason='exported')
        write2file = partial(write_func,
                            suffix=passkey_suffix,
                            parser=parser)
        
        def json_serializer():
            new_data = JSONify.convert2strings(data).to_json(indent=2, ensure_ascii=False)
            passkey_suffix = self._Suffix._JSON
            write2file = partial(write_func,
                                suffix=passkey_suffix,
                                data=new_data)
            return write2file
        
        if self._jserializer:
            write2file = json_serializer()
        
        try:
            parser.update(**data)
        except ValueError:
            CipherException(
                f'Passphrases containing special characters are not suitable for .INI configurations. '
                'Serializing in JSON (.json) format to accommodate special characters.',
                log_method=logger.error)
            write2file = json_serializer()
        
        if self.export_passkey:
            write2file()
    
    def encrypt_file(self) -> NamedTuple:
        self._log_separator('encrypting-file')
        self._print_header(cls_name:=(self.__class__.__name__.upper()))
        _file = self._file
        
        CEinfo = self._log_verbose
        CEinfo(f'{cls_name} encryption algorithm has begun. Gathering prerequisites to encrypt {_file.name!r}...')
        CEinfo("Calculating files hash value as a saftey precaution to ensure data integrity when decrypting.")
        
        hash_val = self._calc_file_hash(_file)
        kdf = self._get_pbk(iterations=self._iterations,
                            hash_type=self._hash_type)
        pbk_name = kdf.__class__.__name__
        
        CEinfo(f'Acquiring the salt value from {pbk_name} to enhance the security of the cryptographic processes. '
                'This guarantees the uniqueness of each derived key, '
                'safeguarding against diverse rainbow table and brute-force attacks.')
        
        salt_val = kdf._salt
        CEinfo(f'Successfully obtained the salt value from {pbk_name}. '
                'The integrity of the cryptographic processes is now fortified.')
        CEinfo(f'Deriving the cryptographic key with iterations over {self._iterations} using {pbk_name} '
                'and obtaining the resulting key for further security measures.')
        
        kdf_key = kdf.derive(self._passkey.encode())
        iv_val = self._gen_random()
        fernet = self._get_cipher(kdf_key, iv_val, hash_type=self._hash_type, algorithm_type=self._algorithm_type)
        cipher_name = fernet.__class__.__name__.upper()
        CEinfo(f'Key successfully acquired. Preparing to read the specified file in bytes mode for encryption purposes '
                f'using cryptographic {cipher_name} encryptor.')
        encryptor = fernet.encryptor()
        
        CEinfo(f"Reading files unencrypted data in bytes mode to store into memory for encryption.")
        plain_btext = self._bytes_read(_file)
        plain_id = self._find_mem_loc(plain_btext)
        
        CEinfo(f"Ensuring the absence of {cls_name}'s encryption identifier "
                'to uphold its integrity by preventing any inadvertent or accidental re-encryption.')
        
        if plain_btext.startswith(self._identifier):
            raise CipherException(
            f'{cls_name} encrypter identification detected signaling that the file {_file!r} is already encrypted. '
            '\nRe-encrypting it poses a significant risk of resulting in inaccurate decryption, potentially leading to irreversible data corruption. '
            '\nIt is crucial to decrypt the file before attempting any further encryption.'
            '\n\nStrictly limit the encryption process to once per file for each subsequent decryption to safeguard against catastrophic data loss.'
            )
        
        CEinfo('No encryption ID found. File is suitable for encryption.')
        CEinfo(f'Securely encrypting stored bytes located at memory address: ({plain_id})...')
        CEinfo('Encrypting stored bytes...')
        
        encrypted = encryptor.update(plain_btext) + encryptor.finalize()
        encrypted_id = self._find_mem_loc(encrypted)
        CEinfo(f'The encrypted data has been securely processed '
                f'while ensuring the integrity of memory location ({encrypted_id}). '
                'Commencing the file writing process.')
        
        if self.backup_file or self.overwrite_file:
            self._create_backup(_file)
        
        new_path = _file.parent
        default_suffix = self._Suffix._AES
        
        if self.overwrite_file:
            encr_file = (new_path / _file.stem).as_posix()
            CEinfo(f'Overwriting {_file!r}...')
            os.remove(_file)
        else:
            if _file.is_file():
                prefix = self._Suffix._PRE_ENC
                _name = _file.stem.removeprefix(prefix)
                if re.search(r'\.', _name):
                    _name = _file.stem.split('.')[0]
                encr_file = (_file.parent / f'{prefix}_{_name}').as_posix()
        
        
        encr_file = Path(encr_file).with_suffix(f'.{default_suffix}')
        encryption_data = (self._identifier + salt_val + iv_val + encrypted)
        self._write2file(encr_file,
                        suffix=default_suffix, mode='wb',
                        data=encryption_data, reason='exported',
                        verbose=self.verbose)
        
        cparser = self._new_parser()
        passkey_name = self.file_name or Path(f'{encr_file.stem}_passkey')
        passkey_file = new_path / passkey_name
        passkey_tuple = self._create_subclass('Encrypter',
                                            ('original_file',
                                            'encrypted_file',
                                            'decipher_key', 'hash_value'),
                                            values=(_file.as_posix(),
                                                    encr_file.as_posix(),
                                                    self._passkey, hash_val)
                                            )
        encr_data = self._new_template(**passkey_tuple._asdict())
        self._export_passkey(parser=cparser,
                            passkey_file=passkey_file,
                            data=encr_data)
        CEinfo(f'{cls_name} encryption algorithm is now finished without encountering any errors for {_file}. '
                f'Kindly utilize the cipher key stored in {passkey_file} to decrypt at anytime.')
        self._print_header(cls_name, activated=False, with_iterations=False)
        return passkey_tuple
    
    def encrypt_text(self) -> NamedTuple:
        self._log_separator('encrypting-text')
        print_header = partial(self._print_header, 'CipherText')
        print_header()
        
        org_text = self._validate_object(self.text, type_is=str)
        hashed_text = self._calc_str_hash(org_text)
        _kdf = self._get_pbk(iterations=self._iterations,
                            hash_type=self._hash_type)
        salt = _kdf._salt
        passkey = _kdf.derive(self._passkey.encode())
        _iv = self._gen_random()
        fernet = self._get_cipher(passkey, _iv, hash_type=self._hash_type, algorithm_type=self._algorithm_type)
        encryptor = fernet.encryptor()
        cipher_text = encryptor.update(org_text.encode()) + encryptor.finalize()
        _base64 = lambda _x: self._base64_key(_x).decode()
        encrypted_data = self._create_subclass(
                            self.__class__.__name__,
                            field_names=('original_text', 'encrypted_text',
                                        'decipher_key', 'hash_value', 'iterations',
                                        'salt_value', 'iv_value', 'hash_type', 'algorithm_type'),
                            values=(org_text, _base64(cipher_text),
                                    self._passkey, hashed_text,
                                    self._iterations, salt.hex(),
                                    _iv.hex(), self._hash_type, self._algorithm_type)
                            )
        
        if self.export_passkey:
            passkey_file = self.file_name or 'ciphertext_passkey'
            if self.export_path:
                passkey_file = Path(self.export_path) / passkey_file
            cparser = self._new_parser()
            _encrypted_data = self._new_template(**encrypted_data._asdict())
            self._export_passkey(parser=cparser,
                                passkey_file=passkey_file,
                                data=_encrypted_data)
        
        print_header(with_iterations=False, activated=False)
        return encrypted_data
    
    @classmethod
    def quick_encrypt(cls,
                        *,
                        text: str,
                        file_name: str=None,
                        export_path: str=None
                        ) -> NamedTuple:
        cls._log_separator('quick-encrypting-text')
        print_header = partial(cls._print_header, cls, 'Quick-CipherText')
        print_header()
        file = file_name or 'quick_ciphertext_passkey'
        encrypted_text = cls(text=text,
                            file_name=file,
                            min_power=True,
                            export_passkey=True,
                            export_path=export_path).encrypt_text()
        print_header(with_iterations=False, activated=False)
        return encrypted_text


@dataclass(kw_only=True)
class DecipherEngine(_BaseEngine):
    """
    DecipherEngine is a class designed to decrypt data encrypted through the CipherEngine.
    
    This class specifically operates with configuration files generated by the CipherEngine during the encryption process.
    """
    __slots__ = CipherEngine.__slots__
    
    def __post_init__(self):
        super().__init__(passkey_file=self.passkey_file,
                        verbose=self.verbose,
                        overwrite_file=self.overwrite_file,
                        ciphertuple=self.ciphertuple)
        self._get_dependencies()
    
    def _get_dependencies(self):
        """
        Internal method to fetch and parse necessary dependencies for the decryption process.
        """
        #** For configuration files (.INI | .JSON)
        if self.passkey_file:
            self._passkey_file = self._validate_file(self.passkey_file)
            cparser_func = partial(self._parse_config, self._passkey_file)
            self._iterations = int(ast.literal_eval(cparser_func(section_key='iterations')))
            self._hash_val = cparser_func(section_key='hash_value')
            self._hash_type = cparser_func(section_key='hash_type').split('.')[-1].rstrip(">'")
            self._algorithm_type = cparser_func(section_key='algorithm_type').split('.')[-1].rstrip(">'")
            self._salt_val = cparser_func(section_key='salt_value')
            self._iv_val = cparser_func(section_key='iv_value')
            sec_getter = lambda _sec_key: cparser_func(section='CIPHER_INFO', section_key=_sec_key)
            self._encrypted_text = sec_getter('encrypted_text')
            self._encrypted_file = sec_getter('encrypted_file')
            self._decipher_key = sec_getter('decipher_key')
        
        #** For CipherTuple instances.
        if self.ciphertuple:
            self._ciphertuple = self._validate_ciphertuple(self.ciphertuple)
    
    def decrypt_file(self) -> None | NoReturn:
        self._log_separator('decrypting-file')
        
        config_path = self._passkey_file
        cls_name = self.__class__.__name__.upper()
        print_header = partial(
                        self._print_header,
                        cls_name,
                        with_iterations=False,
                        encrypting=False
                        )
        print_header(activated=True)
        
        CEerror = self._log_verbose
        _suffix = self._Suffix._DEC
        CEerror(f'{cls_name} decryption algorithm has begun. Gathering prerequisites...')
        
        CEerror(f"Deriving security dependencies values from specified ({config_path!r}) configuration file.")
        cipher_info = 'CIPHER_INFO'
        security_par = 'SECURITY_PARAMS'
        cparser_func = partial(self._parse_config, config_path)
        hashed_value = cparser_func(section=security_par, section_key='hash_value')
        _file = self._validate_file(self._encrypted_file)
        CEerror(f"{cipher_info} dependencies ('encrypted_file', 'decipher_key') obtained.")
        CEerror(f"{security_par} dependencies ('iterations', 'hash_value', 'decipher_key') obtained.")
        
        _data = self._bytes_read(_file)
        _data_id = self._find_mem_loc(_data)
        CEerror(f'File has been read in bytes mode and stored into memory location at ({_data_id}).')
        
        CEerror(f"Verifying that the file contains an encryption identifier that aligns with {cls_name}'s identifier.")
        if _data.startswith(self._identifier):
            _encrypted_data = _data[len(self._identifier):]
            CEerror('Identification found and verified. Parsing files encrypted bytes.')
            _salt = _encrypted_data[:16]
            _iv = _encrypted_data[16:32]
            _cipher_text = _encrypted_data[32:]
            _kdf = self._get_pbk(_salt, iterations=self._iterations, hash_type=self._hash_type)
            _kdf_name = _kdf.__class__.__name__.upper()
            _key = _kdf.derive(self._decipher_key.encode())
            CEerror(f'Derived key from {_kdf_name}. Initializing decryption tool.')
            try:
                CEerror('Fetching decryptor...')
                fernet = self._get_cipher(_key, _iv, hash_type=self._hash_type, algorithm_type=self._algorithm_type)
            except ValueError as v_error:
                _v_name = v_error.__class__.__name__.upper()
                raise CipherException(
                        f'An error occurred while attempting to decrypt {_file.name!r}. '
                        f'Please ensure the file is already encrypted.\n[{_v_name}] {v_error}'
                        )
            
            c_decryptor = fernet.decryptor()
            c_decrypted = c_decryptor.update(_cipher_text) + c_decryptor.finalize()
            c_decrypted_id = self._find_mem_loc(c_decrypted)
            CEerror(
                f'Decrypting stored bytes at memory location ({c_decrypted_id}).'
                )
            CEerror('Writing decrypted data to file.')
            if self.overwrite_file:
                CEerror(f'Overwriting {_file}')
                _suffix = _file.name.split('.')[-1]
                decrypted_file = _file.as_posix()
                os.remove(_file)
            else:
                if _file.is_file():
                    prefix = self._Suffix._PRE_DEC
                    _name = _file.stem.removeprefix(prefix)
                    if re.search(r'\.', _name):
                        _name = _file.stem.split('.')[0]
                    decrypted_file = (_file.parent / f'{prefix}_{_name}').as_posix()
            
            decrypted_file = Path(decrypted_file)
            self._write2file(decrypted_file,
                            suffix=_suffix, mode='wb',
                            data=c_decrypted, reason='decrypted',
                            verbose=self.verbose)
            
            CEerror('Verifying the hash value against the decrypted file for validation.')
            check_decrypted = self._calc_file_hash(decrypted_file.with_suffix('.'+_suffix))
            if (check_decrypted != hashed_value):
                self._failed_hash(hashed_value, check_decrypted)
            
            CEerror('The matching hashed values affirm that no data loss occurred during the decryption process.')
            CEerror(f'{cls_name} decryption algorithm is now finished without encountering any errors for {_file}.')
            print_header(activated=False, with_iterations=False)
            return
        else:
            raise CipherException(
                f'The file {_file!r} lacks the required identifier. '
                f"\n{cls_name}'s decryption algorithm only operates with files containing its designated identifier. "
                f'\nEncryption algorithms identifier:\n{self._identifier}')
    
    @classmethod
    def _get_subclass(cls):
        return cls._create_subclass(
            cls.__class__.__name__,
            field_names=('decrypted_text', 'hash_value')
        )
    
    def decrypt_text(self) -> NamedTuple:
        self._log_separator('decrypting-text')
        print_header = partial(
                        self._print_header,
                        'DecipherText',
                        with_iterations=False,
                        encrypting=False
                        )
        print_header(activated=True)
        
        if self.ciphertuple:
            salt = self._ciphertuple.salt_value
            iv = self._ciphertuple.iv_value
            iterations = self._ciphertuple.iterations
            encrypted_text = self._ciphertuple.encrypted_text
            hash_val = self._ciphertuple.hash_value
            decipher_key = self._ciphertuple.decipher_key
            hash_type = self._ciphertuple.hash_type
            algorithm_type = self._ciphertuple.algorithm_type
        elif self.passkey_file:
            salt = self._salt_val
            iv = self._iv_val
            iterations = self._iterations
            encrypted_text = self._encrypted_text
            hash_val = self._hash_val
            decipher_key = self._decipher_key
            hash_type = self._hash_type
            algorithm_type = self._algorithm_type
        
        bsalt = bytes.fromhex(salt)
        biv = bytes.fromhex(iv)
        kdf = self._get_pbk(bsalt, iterations=iterations, hash_type=hash_type)
        passkey = kdf.derive(decipher_key.encode())
        fernet = self._get_cipher(passkey, biv, hash_type=hash_type, algorithm_type=algorithm_type)
        decryptor = fernet.decryptor()
        decrypted_text = decryptor.update(base64.urlsafe_b64decode(encrypted_text)) + decryptor.finalize()
        decrypted_hash = self._calc_str_hash(decrypted_text.decode())
        if hash_val != decrypted_hash:
            self._failed_hash(hash_val, decrypted_hash)
        decr_tuple = self._get_subclass()
        print_header(activated=False)
        return decr_tuple(decrypted_text.decode(), decrypted_hash)
    
    @classmethod
    def quick_decrypt(cls, ciphertuple: NamedTuple=None) -> str:
        print_header = partial(cls._print_header, cls,
                        'Quick-DecipherText',
                        with_iterations=False,
                        encrypting=False
                        )
        print_header(activated=True)
        decrypted_text = cls(ciphertuple=ciphertuple).decrypt_text()
        print_header(activated=False)
        return decrypted_text


def generate_crypto_key(**kwargs):
    """
    ### Generate a cryptographic key.
    
    #### Parameters:
        - key_length (Union[int, str]): The length of the key. Defaults to 32.
            - Important Note: key_length soley depends on the max_tokens count.
            Length must be greater than max_tokens count.
        - exclude (Union[str, Iterable]): Characters to exclude from the key generation.
        Can be a string or an iterable of characters. Defaults to an empty string.
        - include_all_chars (bool): If True, include all characters from digits, ascii_letters, and punctuation.
        Defaults to False.
        - repeat (int): The number of iterations for character cycling. Defaults to 64.
        - Note: 'repeat' parameter is used for character cycling from itertools.repeat,
        and its input is not explicitly needed as its entire purpose is to adjust the key length.
        If the absolute difference between 'repeat' and 'key_length' is within a certain threshold (1e5),
        the 'repeat' value will be adjusted as max(max(repeat, key_length), threshold). \n
        >>> if abs(repeat - key_length) <= threshold (1e5)
        >>> new repeat value -> max(max(repeat, key_length), threshold)
        
    #### Returns:
        - str: The generated cryptographic key.
        
    #### Raises:
        - CipherException:
            - If conflicting exclude and include_all_chars arguments are specified
            - If exclude is not of type Iterable
            - If key_length is less than default value (32)
            
    #### Note:
        - The default key includes digits and ascii_letters only.
    """
    return _BaseEngine._generate_key(**kwargs)

def quick_ciphertext(**kwargs):
    """
    ### Quickly encrypts text data and exports necessary information.
    
    #### Parameters:
        - text: Any: The text to be encrypted.
        - file_name: str: The name of the output file containing encryption details (default: 'ciphertext_info').
        - export_passkey: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
        - export_path: Any | None: The path to export the output file (default: None).
        - verbose: bool: Flag indicating whether to print verbose messages (default: False).
    
    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    
    #### Example:
    >>> result = quick_ciphertext(text='Hello, World!')
    >>> print(result.encrypted_text)
    "abcdef1234567890..."
    """
    return CipherEngine.quick_encrypt(**kwargs)

def quick_deciphertext(**kwargs):
    """
    ### Quickly decrypts text data using provided details.
    
    #### Parameters:
        - ciphertuple: NamedTuple: The NamedTuple class generated from the quick encryption process.
        - text: Any | None: The encrypted text to be decrypted.
        - decipher_key: Any | None: The decryption passphrase or key.
        - hash_value: Any | None: The hash value of the original data.
        - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).
    
    #### Returns:
        - str: Decrypted text.
    
    #### Example:
    >>> result = quick_deciphertext(text='abcdef1234567890...', decipher_key='my_secret_key', hash_value='...')
    >>> print(result)
    "Hello, World!"
    """
    return DecipherEngine.quick_decrypt(**kwargs)

def encrypt_text(**kwargs) -> NamedTuple:
    """
    ### Encrypts a specified text and exports necessary information.
    
    #### Parameters:
        - text: str: The text to be encrypted.
        - key_length: int | None: The length of the cryptographic key (default: 32).
        - passkey_file: str: The name of the output file containing encryption details (default: 'info').
        - passkey: str | int | None: The passphrase or key for encryption (default: None).
        - iterations: int | None: The number of iterations for key derivation (default: None).
        - exclude_chars: list | str: Characters to exclude during passphrase generation (default: '').
        - include_all_chars: bool | None: Flag indicating whether to include all characters during passphrase generation (default: False).
        - export_passkey: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
        - export_path: Any | None: The path to export the output file (default: None).
        - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).
    
    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    
    #### Example:
    >>> result = encrypt_text(text='Hello, World!')
    >>> print(result.encrypted_text)
    "abcdef1234567890..."
    """
    return CipherEngine(**kwargs).encrypt_text()

def decrypt_text(**kwargs) -> NamedTuple:
    """
    ### Decrypts a specified file using encryption details stored in the provided configuration file \
        generated during the encryption process.
    
    ### Parameters:
        - ciphertuple (NamedTuple): The tuple generated from any encryption process to be used for decryption.
        - passkey_file: str | Path: The path to the file containing the encryption details.
        - export_path: str | Path: The path to export the output file (default: None).
        - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).

    #### Returns:
    - str: Decrypted text.
    
    #### Example:
    >>> result = decrypt_text(passkey_file='ciphertext_info', export_path='decrypted')
    >>> print(result)
    "Hello, World!"
    """
    return DecipherEngine(**kwargs).decrypt_text()

def encrypt_file(**kwargs) -> NamedTuple:
    """
    ### Encrypts a specified file and exports necessary information.
    
    #### Parameters:
        - file: str | Path: The path to the file to be encrypted.
        - passkey: str | int | None: The passphrase or key for encryption (default: None).
        - key_length: int | None: The length of the cryptographic key (default: 32).
        - iterations: int | None: The number of iterations for key derivation (default: None).
        - exclude_chars: list | str: Characters to exclude during passphrase generation (default: '').
        - backup_file: bool | None: Flag indicating whether to create a backup of the original file (default: True).
        - overwrite_file: bool | None: Flag indicating whether to overwrite the original file during encryption (default: False).
        - export_passkey: bool | None: Flag indicating whether to export the passphrase to a separate file (default: True).
        - include_all_chars: bool | None: Flag indicating whether to include all characters during passphrase generation (default: False).
        - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).
        - min_power: bool | None: Flag indicating whether to use the minimum power for key derivation (default: False).
        - max_power: bool | None: Flag indicating whether to use the maximum power for key derivation (default: False).
    
    #### Returns:
        - NamedTuple: Tuple containing information about the encryption process.
    
    #### Example:
    >>> result = encrypt_file(file='example.txt', passkey='my_secret_key', iterations=1000)
    >>> print(result.encrypted_file)
    "/path/to/encrypted_file.aes"
    """
    return CipherEngine(**kwargs).encrypt_file()

def decrypt_file(**kwargs) -> str:
    """
    ### Decrypts a specified file using encryption details stored in the provided configuration file \
    generated during the encryption process.
    
    #### Parameters:
        - passkey_file: str | Path: The path to the file containing the encryption details.
        - overwrite_file: bool | None: Flag indicating whether to overwrite the original file during decryption (default: False).
        - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).
    
    #### Returns:
        - str: Path to the decrypted file.
    
    #### Example:
    >>> result = decrypt_file(passkey_file='ciphertext_info', overwrite_file=True)
    >>> print(result)
    "/path/to/decrypted_file.txt"
    """
    return DecipherEngine(**kwargs).decrypt_file()