import os
import re
import sys
import ctypes
import base64
import hashlib
import shutil
import logging
import psutil
import secrets
import numpy as np
import configparser
from pathlib import Path
from logging import Logger
from ast import literal_eval
from datetime import datetime
from functools import partial
from random import SystemRandom
from itertools import cycle, islice
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from collections import OrderedDict, namedtuple
from string import digits, punctuation, ascii_letters
from typing import (Any, AnyStr, Dict, Iterable,
                    Literal, NamedTuple, TypeVar,
                    Optional, Union)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from abc import ABCMeta, abstractmethod

__all__ = ('encrypt_file', 'decrypt_file',
            'encrypt_text', 'decrypt_text',
            'quick_encrypt_text', 'quick_decrypt_text')


P = TypeVar('P', str, Path)
B = TypeVar('B', bool, None)

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
    
    _file_name = Path(__file__).with_suffix('.log')
    _formatter_kwgs = {**{'fmt': '[%(asctime)s][LOG %(levelname)s]:%(message)s',
                        'datefmt': '%Y-%m-%d %I:%M:%S %p'},
                       **(formatter_kwgs or {})}
    _handler_kwgs = {**{'filename': _file_name, 'mode': mode},
                    **(handler_kwgs or {})}
    
    formatter = logging.Formatter(**_formatter_kwgs)
    
    if write_log:
        file_handler = logging.FileHandler(**_handler_kwgs)
        file_handler.setFormatter(formatter)
        _logger.addHandler(file_handler)
    else:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        _logger.addHandler(stream_handler)
    
    return _logger

logger = get_logger(level=logging.DEBUG,
                    write_log=True)

class CipherException(BaseException):
    def __init__(self, *args, log_method: logging=logger.critical):
        self.log_method = log_method
        super().__init__(*args)
        self.log_method(*args)

@dataclass_json
class JSONify(Dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class _BaseSuffix(NamedTuple):
    """
    Enumeration class for common suffixes used in the CipherEngine operations.
    
    Attributes:
    - _AES: str: Suffix for AES encryption.
    - _DEC: str: Suffix for decrypted files.
    - _CFB: str: Suffix for Cipher Feedback (CFB) mode.
    - _INI: str: Suffix for INI configuration files.
    - _JSON: str: Suffix for JSON configuration files.
    - _PRE_ENC: str: Prefix for encrypted files.
    - _PRE_DEC: str: Prefix for decrypted files.
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
        _clock_spd = self._SPEED
        if _clock_spd is None:
            _clock_spd = self._get_clock_speed()
        return _clock_spd
    
    @property
    def cpu_power(self):
        _cpu_power = self._POWER
        if _cpu_power is None:
            _cpu_power = self._get_cpu_power()
        return _cpu_power
    
    def calculate_cpu(self, **kwargs):
        return self._get_cpu_power(**kwargs)
    
    @property
    def get_cpu_chart(self):
        '''CPU _Power Chart'''
        return self._get_cpu_power(return_dict=True)
    
    @classmethod
    def _get_clock_speed(cls) -> NamedTuple:
        _Speed = namedtuple('ClockSpeed', ('speed', 'unit'))
        frequencies = psutil.cpu_freq(percpu=False)
        if frequencies:
            _mega, _giga = cls._Suffix._MHZ, cls._Suffix._GHZ
            _clock_speed = frequencies.max / 1000
            _unit = _giga if _clock_speed >= 1 else _mega
            return _Speed(_clock_speed, _unit)
        raise CipherException(
            'Unable to retrieve CPU frequency information to determine systems clock speed.'
            )
    
    @classmethod
    def _sig_larger(cls, *args) -> NamedTuple:
        '''Significant difference between key_length and max_tokens'''
        _valid_args = all((isinstance(arg, (int, float)) for arg in args))
        _threshold = cls._MAX_TOKENS
        if len(args) == 2 and _valid_args:
            _Sig = namedtuple('SigLarger', ('status', 'threshold'))
            *args, = map(_BaseEngine._validate_object, args)
            _abs_diff = abs(args[1] - args[0])
            _status = (_abs_diff >= _threshold)
            return _Sig(_status, min(max(args), _threshold))
        raise CipherException(
            'Excessive arguments provided; requires precisely two numerical values, such as integers or floats.'
            )
    
    def _get_cpu_power(self,
                    min_power=False,
                    max_power=False,
                    return_dict=False) -> Union[int, Dict[int, int]]:
        """
        ### Calculate and return a recommended CPU power value based on the number of CPU cores.

        #### Parameters:
            - min_power (bool): If True, considers minimum power constraints.
            - max_power (bool): If True, considers maximum power constraints.
            - return_dict (bool): If True, returns the CPU power chart as a dictionary.
        
        #### Note:
        - The calculation is based on a base power value derived from a linearly spaced range.
        - The user's CPU count is used to determine the recommended power,
        with a minimum of 2 cores and a maximum of 64 cores considered.
        - This method utilizes NumPy for efficient array operations.
        
        #### Returns:
        - Union[int, Dict[int, int]]: If return_dict is True, returns the CPU power chart as a dictionary.
        Otherwise, calculates and returns the total power based on specified conditions.
        """
        
        _min_cores = self._MIN_CORES
        _min_cap = self._MIN_CAPACITY
        _max_cap = self._MAX_CAPACITY
        
        if all((min_power, max_power)):
            max_power = False
        
        _default_min = self.min_cores
        _default_max = self.max_cores
        _base_power_range = np.arange(_min_cores, _min_cap, 0.1 if max_power else 0.01)
        _base_power = _base_power_range[_default_max - 1] * _min_cap
        _cpu_counts = np.arange(_default_min, _default_max + 1)
        _cpu_powers = np.multiply(_base_power, _cpu_counts, order='C', subok=True).astype('int64')
        _cpu_chart = OrderedDict(zip(_cpu_counts, _cpu_powers))
        
        if return_dict:
            return _cpu_chart
        
        _total_power = _cpu_chart[_default_min + min((_default_min % 10,
                                                    _default_max % 10))]
        
        _pop_chart = _cpu_chart.popitem
        _last = lambda _x: next(iter(_x[slice(-1, None, None)]))
        if min_power or _total_power >= _max_cap:
            _total_power = _last(_pop_chart(last=False))
        if max_power:
            _total_power =  _last(_pop_chart())
        
        return _total_power
    
    @classmethod
    def _capacity_error(cls, *args):
        raise CipherException(
            f"The specified repetition count surpasses the computational capacity required for {cls.__name__!r}. "
            " It is recommended to use a count of 100 <= x <= 1000, considering the specified 'key_length'. "
            f' {(*args,)}')
    
    @property
    def default_cpu_count(self):
        return os.cpu_count() or 1
    
    @property
    def max_cores(self):
        _os_count = self.default_cpu_count
        _default_max = self._MAX_CORES
        if _default_max < _os_count:
            _default_max = _os_count
        return _default_max
    
    @property
    def min_cores(self):
        _os_count = self.default_cpu_count
        _default_min = self._MIN_CORES
        if _os_count < _default_min:
            _default_min = _os_count
        return _default_min

class ConfigParser(configparser.ConfigParser):
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
    
    def convert_value(self, value):
        _value = str(value).lower()
        _vals = {'true': True, 'false': False, 'none': None}
        return _vals.get(_value, value)

@dataclass(kw_only=True)
class _BaseEngine(_BasePower):
    """
    Base class for the CipherEngine hierarchy, providing common attributes and functionality for encryption.
    
    Attributes:
    - file: Path | None: The path to the file to be processed (default: None).
    - text: str | None: The text data to be processed (default: None).
    - passkey_file: Path | None: The path to the file containing the encryption details (default: None).
    - export_path: Path | None: The path where exported files will be stored (default: None).
    - verbose: bool: Flag indicating whether to print verbose messages (default: False).
    - overwrite_file: bool: Flag indicating whether to overwrite the original file during processing (default: False).
    
    Class Attributes:
    - _BACKEND: cryptography.hazmat.backends.Backend: The cryptography backend used for cryptographic operations.
    - _ALL_CHARS: str: A string containing all possible characters for passphrase generation.
    - _MIN_KEYLENGTH: int: The minimum length for cryptographic keys (default: 32).
    - _MIN_PBKLEN: int: The minimum length for key derivation using PBKDF2 (default: 32).
    - _MAX_KEYLENGTH: int: The maximum length for cryptographic keys, derived from the _BasePower class.
    
    """
    file: P = field(repr=False, default=None)
    text: P = field(repr=False, default=None)
    passkey_file: P = field(repr=False, default=None)
    export_path: P = field(repr=False, default=None)
    verbose: B = field(repr=False, default=False)
    overwrite_file: B = field(repr=False, default=False)
    
    _BACKEND = default_backend
    _ALL_CHARS = (digits + punctuation + ascii_letters)
    _MIN_KEYLENGTH = _MIN_PBKLEN = 32
    _MAX_KEYLENGTH = _BasePower._MAX_CAPACITY
    
    @property
    def identifier(self):
        return f'-----BEGIN CIPHERENGINE AES ENCRYPTED KEY-----'.encode()
    
    @staticmethod
    def _new_parser() -> ConfigParser:
        return ConfigParser()
    
    def _log_verbose(self, __msg, lg_method=logger.info):
        if self.verbose:
            CipherException(__msg, log_method=lg_method)
    
    @classmethod
    def _new_fernet(cls, __key):
        _fernet = partial(Fernet, backend=cls._BACKEND())
        try:
            _new_fernet = _fernet(__key)
        except ValueError:
            _key = cls._base64_key(__key.encode())
            _new_fernet = _fernet(_key)
        return _new_fernet
    
    @staticmethod
    def _failed_hash(org_hash, second_hash):
        raise CipherException(
            'The discrepancy in hashed values points to a critical integrity issue. '
            'Immediate data investigation and remedial action are strongly recommended.'
            f'\nOriginal Hash: {org_hash}'
            f'\nDecrypted Hash: {second_hash}'
        )
    
    def _print_header(self, __name=None,
                            encrypting=True,
                            with_iterations=True,
                            activated=True):
        """
        Prints the main header for activating/deactivating the tool.
        
        Args:
            - name (Optional[str]): The name to display in the header. If None, the class name in uppercase is used.
            - encrypting (bool): If True, indicates encryption; otherwise, decryption.
            - with_iterations (bool): If True, includes the number of iterations in the header.
            - activated (bool): If True, the tool is activated in green; otherwise, deactivated.
        """
        
        _name = __name or self.__class__.__name__.upper()
        if self.verbose:
            _iter_str = f' (iterations={self._iterations:_})'
            _header = '{} {} Tool {}{}'.format(
                                    _name,
                                    'decryption' if not encrypting else 'encryption',
                                    'Activated' if activated else 'Deactivated',
                                    _iter_str if with_iterations else '').upper()
            _color = '31' if not activated else '32'
            print(
            '\033[1;{}m{}\033[0m'.format(_color, _header.center(self._terminal_size, '*'), flush=True)
            )
    
    def _new_template(self, **kwargs) -> Dict:
        '''
        #### \
        This method creates a dynamic template incorporating encryption parameters and security details \
        suitable for writing encrypted data to a file. \
        The generated template can later be employed in the decryption process.
        '''
        _suffix = self._Suffix
        _hash_val = kwargs.pop(_hash_str:=('hash_value'), None)
        _iterations = kwargs.pop(_iter_str:=('iterations'), self.cpu_power)
        return {'CIPHER_INFO': {**kwargs},
                'SECURITY_PARAMS':
                    {_iter_str: _iterations,
                    'algorithm': _suffix._AES.upper() + '-256',
                    'mode': _suffix._CFB,
                    _hash_str: _hash_val,
                    }
                }
    
    @staticmethod
    def _format_file(__file):
        _now = datetime.now()
        _dtime = _now.strftime('%Y-%m-%dT%I:%M:%S%p')
        return _dtime +  __file.as_posix()
    
    @staticmethod
    def _bytes_read(__file) -> bytes:
        with open(__file, mode='rb') as _file:
            _text = _file.read()
        return _text
    
    @classmethod
    def _create_subclass(cls,
                        typename='FieldTuple',
                        /,
                        field_names=None,
                        *,
                        rename=False, module=None,
                        defaults=None, 
                        values: Iterable=None,
                        field_doc='Tuple containing dependecies for decryption purposes.',
                        **kwargs):
        """
        Create a dynamically generated namedtuple subclass.

        Parameters:
        - typename (str): Name of the named tuple subclass.
        - field_names (List[str]): List of field names.
        - rename (bool): Whether to rename invalid field names.
        - module (str): Module name for the namedtuple subclass.
        - defaults (Tuple): Default values for fields.
        - num_attrs (int): Number of default attributes if field_names is not provided.
        - **kwargs: Additional parameters.
            - num_attrs (int): The number of default attributes assigned to the object when no specific field names are provided.
            - field_doc (str): List of documentation strings for each field.

        Returns:
        - Named tuple subclass.
        """
        
        num_attrs = kwargs.pop('num_attrs', 5)
        if not isinstance(num_attrs, int) or num_attrs <= 0:
            raise CipherException(f"{num_attrs!r} is not a positive integer.")

        _field_names = field_names or np.core.defchararray.add('attr', np.arange(1, num_attrs+1).astype(str))
        _none_generator = lambda _type=None: (_type,) * len(_field_names)
        _defaults = defaults or _none_generator()
        _field_docs = field_doc or _none_generator('')
        _module = module or typename
        _new_tuple = namedtuple(typename=typename,
                                field_names=_field_names,
                                rename=rename,
                                defaults=_defaults,
                                module=_module)
        setattr(_new_tuple, '__doc__', _field_docs)
        if values:
            return _new_tuple(*values)
        return _new_tuple
    
    @staticmethod
    def _validate_file(__file) -> Path:
        try:
            _file = Path(__file)
        except TypeError as t_error:
            raise CipherException(t_error)
        
        if not _file:
            raise CipherException(f"File arugment must not be empty: {_file!r}")
        elif not _file.exists():
            raise CipherException(f"File does not exist: {_file!r}. Please check system files.")
        elif (not _file.is_file()) and (not _file.is_absolute()):
            raise CipherException(f"Invalid path type: {_file!r}. Path must be a file type.")
        elif _file.is_dir():
            raise CipherException(f"File is a directory: {_file!r}. Argument must be a valid file.")
        return _file
    
    @property
    def _terminal_size(self) -> int:
        return shutil.get_terminal_size().columns
    
    @classmethod
    def _filter_chars(cls, __string, *, exclude='') -> str:
        """
        Filter characters in the given string, excluding those specified.
        
        Parameters:
        - input_string (str): The input string to be filtered.
        - exclude (str): Characters to be excluded from the filtering process.
        
        Returns:
        - str: The filtered string with specified characters excluded.
        """
        _string = ''.join(__string)
        _filtered = _string.translate(str.maketrans('', '', exclude))
        return cls._r_whitespace(_filtered)
    
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
    def _exclude_type(__key) -> str:
        """
        ### Exclude specific character sets based on the provided key.

        #### Parameters:
        - __key (str): The key to select the character set to exclude.

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
        return {'digits': digits,
                'punct': punctuation,
                'ascii': ascii_letters,
                'digits_punct': digits + punctuation,
                'ascii_punct': ascii_letters + punctuation,
                'digits_ascii': digits + ascii_letters
                }.get(__key)
    
    @staticmethod
    def _base64_key(__key):
        try:
            return base64.urlsafe_b64encode(__key)
        except AttributeError as _attr_error:
            raise CipherException(
                f'Failed to derive encoded bytes from {__key!r}. '
                f'\n{_attr_error}'
            )
    
    @staticmethod
    def _calc_file_hash(__file_path):
        """
        Calculate the SHA-256 hash of the content in the specified file.
        
        Parameters:
        - file_path (str): The path to the file for which the hash is to be calculated.
        
        Returns:
        - str: The SHA-256 hash value as a hexadecimal string.
        """
        sha256_hash = hashlib.sha256()
        with open(__file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _calc_str_hash(self, __text):
        """
        Calculate the SHA-256 hash of the provided text.
        
        Parameters:
        - text (str): The input text for which the hash is to be calculated.
        
        Returns:
        - str: The SHA-256 hash value as a hexadecimal string.
        """
        _text = self._validate_object(__text, type_is=str).encode()
        _hash = hashlib.sha256()
        _hash.update(_text)
        return _hash.hexdigest()
    
    @staticmethod
    def _validate_object(__other, type_is=int, arg='Argument'):
        """
        Validate and coerce the input object to the specified type.
        
        Parameters:
        - other (Any): The input object to be validated and coerced.
        - type_is (Type[Any]): The target type for validation and coercion.
        - arg (str): A descriptive label for the argument being validated.
        
        Returns:
        - Any: The validated and coerced object.
        
        Raises:
        - CipherException: If validation or coercion fails.
        
        """
        _CEerror = CipherException
        _possible_instances = (TypeError, ValueError, SyntaxError)
        
        if type_is is Any:
            type_is = type(__other)
        
        if type_is is int:
            try:
                _obj = int(str(__other))
            except _possible_instances:
                raise _CEerror(f'{arg!r} must be of type {int} or integer-like {str}')
        elif type_is is str:
            try:
                _obj = str(__other)
            except _possible_instances:
                raise _CEerror(f'{arg!r} must be of type {str}')
        elif type_is is list:
            try:
                _obj = list(map(str, __other))
            except _possible_instances:
                raise _CEerror(f'{arg!r} must be of type {list} with {int} or integer-like {str}')
        elif type_is is Path:
            try:
                _obj = Path(__other)
            except _possible_instances:
                raise  _CEerror(f'{arg!r} must be of type {Path} or {str}')
        else:
            return
        
        return _obj
    
    @classmethod
    def _generate_key(cls, *,
                    key_length: Union[int, str]=32,
                    exclude: Union[str, Iterable]='',
                    include_all: bool=Literal[False],
                    repeat: int=None):
        """
        ### Generate a cryptographic key.
        
        #### Parameters:
            - key_length (Union[int, str]): The length of the key. Defaults to 32.
                - Important Note: key_length soley depends on the max_tokens count.
                Length must be greater than max_tokens count.
            - exclude (Union[str, Iterable]): Characters to exclude from the key generation.
            Can be a string or an iterable of characters. Defaults to an empty string.
            - include_all (bool): If True, include all characters from digits, ascii_letters, and punctuation.
            Defaults to False.
            - max_tokens (int): The number of iterations for character cycling. Defaults to 1000.
            
        #### Returns:
            - str: The generated cryptographic key.
            
        #### Raises:
            - CipherException:
                - If conflicting exclude and include_all arguments are specified
                - If exclude is not of type Iterable
                - If key_length is less than default value (32)
                
        #### Note:
            - The default key includes digits and ascii_letters only.
        """
        _CEerror = CipherException
        _validator = cls._validate_object
        _filter = cls._filter_chars
        _cpu_power = repeat or _BasePower().cpu_power
        if all((exclude, include_all)):
            raise _CEerror("Cannot specify both 'exclude' and 'include_all' arguments.")
        _key_length = _validator(key_length, type_is=int, arg='key_length')
        _tokens = cls._MAX_TOKENS
        _exclude = _validator(exclude, type_is=Any, arg='exlcude')
        _threshold = cls._sig_larger(_key_length, int(_cpu_power))
        _max_capacity = cls._MAX_CAPACITY
        _min_keylen = cls._MIN_KEYLENGTH
        _max_keylen = cls._MAX_KEYLENGTH
        if any((_key_length < _min_keylen,
                _key_length > _max_keylen)):
            raise _CEerror(f'\'key_length\' must be of value {_min_keylen} <= x <= {_max_keylen}.')
        
        if any((_tokens >= _max_capacity,
                _cpu_power >= _max_capacity,
                _tokens > _cpu_power)):
            
            cls._capacity_error(f'Max Tokens: {_tokens}',
                                f'Character Repeat Count: {_cpu_power}')
        
        if not _threshold.status:
            _tokens = _threshold.threshold
            _CEerror("The specified 'key_length' exceeds the number of characters that can be cycled during repetition."
                    f" Higher values for 'max_tokens' count is recommended for better results ('max_tokens' count is now {_tokens}).",
                    log_method=logger.warning)
        
        _slicer = lambda *args: ''.join(islice(*args, _tokens))
        _all_chars = _slicer(cycle(cls._ALL_CHARS))
        _chars = _filter(_all_chars, exclude=punctuation)
        
        if include_all is True:
            _chars = _all_chars
        
        if exclude:
            _exclude = cls._exclude_type(exclude)
            if not _exclude:
                _chars = _chars
            elif _exclude:
                _chars = _filter(_all_chars, exclude=_exclude)
        
        _min_length = min(_key_length, len(_chars))
        _seed = SystemRandom().sample
        _passkey = ''.join(_seed(population=_chars, k=_min_length))
        return _passkey
    
    @classmethod
    def _parse_config(cls, __config, *, section='SECURITY_PARAMS', section_key) -> Union[str, Any]:
        _CEcritical = CipherException
        _cparser = cls._new_parser()
        try:
            _cparser.read(__config)
            _sec_val = _cparser[section].get(section_key)
        except configparser.NoSectionError:
            raise _CEcritical(f"Confgiuration file does not contain section {section!r}")
        except configparser.NoOptionError:
            raise _CEcritical(f"{section_key.capitalize()!r} was not found in {section!r} section."
                            f"\nIt is imperative that the values stored in the passkey configuration file generated by {cls.__name__.upper()} encryption algorithm tool is saved and not altered in anyway. "
                            "Failure to do so may alter the decryption process, potentially corrupting the files data.")
        except configparser.Error:
            raise _CEcritical(f'An unexpected error occured trying to read {__config.name}.'
                            f'Decryption algorithm only works with its initial iterations value.')
        return _sec_val
    
    @staticmethod
    def _gen_random(__size: int=16) -> bytes:
        return secrets.token_bytes(__size)
    
    @classmethod
    def _get_cipher(cls, __key, __iv=None) -> Cipher:
        if __iv is None:
            __iv = cls._gen_random()
        return Cipher(
                    algorithm=algorithms.AES(__key),
                    mode=modes.CFB(__iv),
                    backend=cls._BACKEND()
                    )
    
    @classmethod
    def _get_pbk(cls, __salt=None, iterations=None) -> PBKDF2HMAC:
        if __salt is None:
            __salt = cls._gen_random()
        return PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=cls._MIN_PBKLEN,
                salt=__salt,
                iterations=iterations,
                backend=cls._BACKEND()
            )
    
    @classmethod
    def _char_checker(cls, __text) -> bool:
        """
        Check the validity of the given passkey.

        Parameters:
        - passkey (str): The passkey to be validated.

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
        if __text:
            return all(_char in cls._ALL_CHARS for _char in __text)
        return False
    
    @staticmethod
    def _r_whitespace(__chars: str) -> str:
        _chars = _BaseEngine._validate_object(__chars, type_is=str)
        return re.sub(r'\s', '', _chars).strip()
    
    @staticmethod
    def _create_backup(__file: Union[str, Path]) -> None:
        _CEinfo = partial(CipherException, log_method=logger.info)
        _backup_path = __file.parent / (_backup:=Path(f'backup/backup-{__file.name}'))
        if not _backup.is_file():
            _CEinfo(
                'No backup folder detected. '
                f'Creating a backup folder named {_backup.parent!r} to store original files securely.'
                )
            _backup_path.parent.mkdir()
        
        _CEinfo(
            f'Backing up {_backup.name} to {_backup}',
            log_method=logger.info
            )
        shutil.copy2(__file, _backup_path)
    
    @staticmethod
    def _write2file(__file: Path,
                    *,
                    suffix: bool='ini', data:AnyStr='',
                    mode: str='w', parser: configparser=None,
                    reason: str='', verbose: bool=False) -> None:
        
        _CEerror = partial(CipherException, log_method=logger.info)
        __file = Path(__file).with_suffix(f'.{suffix}')
        with open(__file, mode=mode) as _file:
            if parser:
                parser.write(_file)
            else:
                _file.write(data)
            _str = partial('{_file!r} has successfully been {reason} as {_path}'.format,
                        _file=_file.name, _path=_file)
            if verbose:
                _CEerror(_str(reason=reason or 'written'))
        return 
    
    @staticmethod
    def _compiler(__defaults, __k) -> bool:
        """
        Validate if the given input matches the provided defaults.

        Args:
            __defaults: Default values to match against (can contain regex patterns)
            __k: Input to validate.

        Returns:
            bool: True if input matches any default, False otherwise.
        """
        _valid_instances = (int, str, bool, bytes, Iterable)
        _join = '|'.join
        if any((not __k,
                not isinstance(__k, _valid_instances),
                hasattr(__k, '__str__'))):
            __k = str(__k)
        
        _defaults = map(re.escape, map(str, __defaults))
        _pattern = _join(_defaults)
        _k = _join(map(re.escape, __k))
        
        _compiled = re.compile(_pattern, re.IGNORECASE).search(_k)
        return bool(_compiled)


@dataclass(kw_only=True)
class CipherEngine(_BaseEngine):
    """
    CipherEngine class for encrypting files and text data using symmetric key cryptography.

    Attributes:
    - passkey: Optional[Union[str, int]]: The passphrase or key for encryption.
    - key_length: Optional[int]: The length of the cryptographic key (default: _BaseEngine._MIN_KEYLENGTH).
    - iterations: Optional[int]: The number of iterations for key derivation.
    - exclude_chars: Union[list, str]: Characters to exclude during passphrase generation (default: None).
    - backup_file: bool: Flag indicating whether to create a backup of the original file (default: True).
    - export_passkey: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
    - include_all_chars: bool: Flag indicating whether to include all characters during passphrase generation (default: False).
    - min_power: bool: Flag indicating whether to use the minimum power for key derivation (default: False).
    - max_power: bool: Flag indicating whether to use the maximum power for key derivation (default: False).

    Methods:
    - encrypt_file(): Encrypts a specified file.
    - encrypt_text(): Encrypts a specified text.
    - quick_encrypt(): Quickly encrypts text data and exports necessary information.

    Example:
    >>> cipher = CipherEngine(passkey='my_secret_key', iterations=1000)
    >>> cipher.encrypt_file()
    """
    __slots__ = ('__weakrefs__', '_passkey', '_iterations',
                'file','text', 'passkey_file', 'export_path',
                'verbose', 'overwrite_file', '_salt')
    
    passkey: Optional[Union[str, int]] = field(init=True, repr=False, default=None)
    key_length: Optional[int] = field(repr=True, default=_BaseEngine._MIN_KEYLENGTH)
    iterations: Optional[int] = field(repr=True, default=None)
    exclude_chars: Union[list, str] = field(repr=True, default=None)
    backup_file: B = field(repr=False, default=Literal[True])
    export_passkey: B = field(repr=False, default=Literal[True])
    include_all_chars: B = field(repr=False, default=Literal[False])
    min_power: B = field(repr=False, default=False)
    max_power: B = field(repr=False, default=False)
    
    def __post_init__(self):
        """
        Perform post-initialization tasks including validating and deriving encryption parameters.
        """
        super().__init__(file=self.file,
                        overwrite_file=self.overwrite_file,
                        verbose=self.verbose,
                        text=self.text)
        
        self._iterations = self._calculate_iterations()
        self._passkey = self._validate_passkey(self.passkey,
                                            key_length=self.key_length,
                                            exclude=self.exclude_chars,
                                            include_all=self.include_all_chars,
                                            repeat=self._iterations)
    
    def _calculate_iterations(self) -> int:
        """
        Calculate the number of iterations for key derivation.

        Returns:
        int: Number of iterations.
        """
        _iterations = self.iterations
        _max_cap = self._MAX_CAPACITY
        if _iterations:
            _iter_count = self._validate_object(_iterations, type_is=int, arg='iterations')
            if _iter_count >= _max_cap:
                return self._capacity_error(f'Specified value: {_iter_count}',
                                            f'Max Iterations value: {_max_cap}')
            return _iter_count
        
        _power_class = partial(self._create_subclass,
                            'PStats', ('min', 'max'),
                            field_doc='Minimum and maximum values for number of iterations.')
        _calculate = self.calculate_cpu
        args = (self.min_power, self.max_power)
        if any(args):
            _power_info = _power_class(values=args)
            return _calculate(min_power=_power_info.min,
                            max_power=_power_info.max)
        return self.cpu_power
    
    @classmethod
    def _validate_passkey(cls, __passkey=None, **kwargs) -> str:
        """
        Validates a given passkey. If the passkey is not provided or contains invalid characters,
        generates a new key based on the specified criteria.
        
        Parameters:
        - __passkey: str | None: The passkey to be validated.
        - **kwargs: Additional keyword arguments for key generation.
        
        Returns:
        str: Validated passkey.
        """
        _key = __passkey
        if any((not _key,
                not cls._char_checker(__passkey))):
            _key = cls._generate_key(**kwargs)
        
        return _key
    
    def encrypt_file(self) -> NamedTuple:
        _cls_name = self.__class__.__name__.upper()
        self._print_header(_cls_name)
        _file = self._validate_file(self.file)
        
        _verbose = self.verbose
        _iterations = self._iterations
        _mem_info = self._find_mem_loc
        _CEinfo = self._log_verbose
        
        _CEinfo(f'{_cls_name} encryption algorithm has begun. Gathering prerequisites to encrypt {_file.name!r}...')
        _CEinfo("Calculating files hash value as a saftey precaution to ensure data integrity when decrypting.")
        _hash_val = self._calc_file_hash(_file)
        
        _passkey = self._passkey
        _kdf = self._get_pbk(iterations=_iterations)
        _pbk_name = _kdf.__class__.__name__
        
        _CEinfo(f'Acquiring the salt value from {_pbk_name} to enhance the security of the cryptographic processes. '
                'This guarantees the uniqueness of each derived key, '
                'safeguarding against diverse rainbow table and brute-force attacks.')
        
        _salt = self._salt = _kdf._salt
        _CEinfo(f'Successfully obtained the salt value from {_pbk_name}. '
                'The integrity of the cryptographic processes is now fortified.')
        _CEinfo(f'Deriving the cryptographic key with iterations over {_iterations} using {_pbk_name} '
                'and obtaining the resulting key for further security measures.')
        
        _key = _kdf.derive(_passkey.encode())
        _iv = self._gen_random()
        _cipher = self._get_cipher(_key, _iv)
        _cipher_name = _cipher.__class__.__name__.upper()
        _CEinfo(f'Key successfully acquired. Preparing to read the specified file in bytes mode for encryption purposes '
                f'using cryptographic {_cipher_name} encryptor.')
        _encryptor = _cipher.encryptor()
        
        _CEinfo(f"Reading files unencrypted data in bytes mode to store into memory for encryption.")
        _plain_text = self._bytes_read(_file)
        _plain_id = _mem_info(_plain_text)
        
        _identifier = self.identifier
        _CEinfo(f"Ensuring the absence of {_cls_name}'s encryption identifier "
                'to uphold its integrity by preventing any inadvertent or accidental re-encryption.')
        
        if _plain_text.startswith(_identifier):
            raise CipherException(
            f'{_cls_name} encrypter identification detected signaling that the file {_file!r} is already encrypted. '
            '\nRe-encrypting it poses a significant risk of resulting in inaccurate decryption, potentially leading to irreversible data corruption. '
            '\nIt is crucial to decrypt the file before attempting any further encryption.'
            '\n\nStrictly limit the encryption process to once per file for each subsequent decryption to safeguard against catastrophic data loss.'
            )
        
        _CEinfo('No encryption ID found. File is suitable for encryption.')
        _CEinfo(f'Securely encrypting stored bytes located at memory address: ({_plain_id})...')
        _CEinfo('Encrypting stored bytes...')
        
        _encrypted = _encryptor.update(_plain_text) + _encryptor.finalize()
        _encrypted_id = _mem_info(_encrypted)
        _CEinfo(f'The encrypted data has been securely processed '
                f'while ensuring the integrity of memory location ({_encrypted_id}). '
                'Commencing the file writing process.')
        
        if self.backup_file or self.overwrite_file:
            self._create_backup(_file)
        
        _new_path = _file.parent
        _default_suffix = self._Suffix._AES
        
        if self.overwrite_file:
            _encr_file = (_new_path / _file.stem).as_posix()
            _CEinfo(f'Overwriting {_file!r}...')
            os.remove(_file)
        else:
            if _file.is_file():
                _prefix = self._Suffix._PRE_ENC
                _name = _file.stem.removeprefix(_prefix)
                if re.search(r'\.', _name):
                    _name = _file.stem.split('.')[0]
                _encr_file = (_file.parent / f'{_prefix}_{_name}').as_posix()
        
        
        _encr_file = Path(_encr_file).with_suffix(f'.{_default_suffix}')
        _encryption_data = (_identifier + _salt + _iv + _encrypted)
        self._write2file(_encr_file,
                        suffix=_default_suffix, mode='wb',
                        data=_encryption_data, reason='exported',
                        verbose=_verbose)
        
        _parser = self._new_parser()
        
        _passkey_suffix = self._Suffix._INI
        _passkey_name = Path(f'{_encr_file.stem}_passkey').with_suffix(f'.{_passkey_suffix}')
        _passkey_file = _new_path / _passkey_name
        
        _write_func = partial(self._write2file,
                            _passkey_file,
                            reason='exported')
        _write2file = partial(_write_func,
                            suffix=_passkey_suffix,
                            parser=_parser,
                            verbose=_verbose)
        _passkey_tuple = self._create_subclass('Encrypter',
                                                ('original_file',
                                                'encrypted_file',
                                                'decipher_key', 'hash_value'),
                                                values=(_file.as_posix(),
                                                        _encr_file.as_posix(),
                                                        _passkey, _hash_val)
                                                )
        _encr_data = self._new_template(**_passkey_tuple._asdict())
        try:
            _parser.update(**_encr_data)
        except ValueError:
            _CEinfo(f'[PASSKEY ERROR] Special characters are not suitable for {ConfigParser.__name__!r} (.INI configurations). '
                    'Serializing as JSON (.json).',
                    lg_method=logger.warning)
            _encr_data = JSONify(**_encr_data).to_json(indent=4)
            _passkey_suffix = self._Suffix._JSON
            _write2file = partial(_write_func,
                                suffix=_passkey_suffix,
                                data=_encr_data,
                                verbose=_verbose)
        
        if self.export_passkey:
            _write2file()
        
        _CEinfo(f'{_cls_name} encryption algorithm is now finished without encountering any errors for {_file}. '
                f'Kindly utilize the cipher key stored in {_passkey_file} to decrypt at anytime.')
        self._print_header(_cls_name, activated=False, with_iterations=False)
        return _passkey_tuple
    
    def encrypt_text(self) -> NamedTuple:
        _text = self._validate_object(self.text, type_is=str)
        _hashed_text = self._calc_str_hash(_text)
        _passphrase = self.passkey
        _pexport = self.export_path
        if not _passphrase:
            _passphrase = self._passkey
        
        _kdf = self._get_pbk(iterations=self._iterations)
        self._salt = base64.urlsafe_b64encode(_kdf._salt)
        _passkey = self._base64_key(_kdf.derive(_passphrase.encode()))
        _cipher = self._new_fernet(_passkey)
        _cipher_text = _cipher.encrypt(_text.encode())
        _base64 = lambda _x: self._base64_key(_x).decode()
        encrypted_data = self._create_subclass(
                            self.__class__.__name__,
                            ('original_text', 'encrypted_text', 'decipher_key'),
                            values=(_text, _base64(_cipher_text), _base64(_passkey))
                            )
        if self.export_passkey:
            _file = Path('ciphertext_info')
            if _pexport:
                _file = Path(_pexport) / _file
            _parser = self._new_parser()
            _encrypted_data = self._new_template(**encrypted_data._asdict(),
                                                hash_value=_hashed_text)
            _parser.update(**_encrypted_data)
            self._write2file(_file,
                            suffix=self._Suffix._INI, mode='w',
                            parser=_parser, verbose=self.verbose)
        return encrypted_data
    
    @classmethod
    def quick_encrypt(cls, *,
                        text,
                        file_name='ciphertext_info',
                        export_passkey=Literal[True],
                        export_path=None,
                        verbose=False) -> NamedTuple:
        
        _hashed_text = cls._calc_str_hash(cls, text)
        _def_iterations = _BasePower().cpu_power
        _passkey = cls._base64_key(cls._generate_key(key_length=32).encode())
        _cipher = cls._new_fernet(_passkey)
        _encrypted_bytes = _cipher.encrypt(text.encode())
        _cipher_text = _encrypted_bytes.hex()
        encrypted_data = cls._create_subclass(cls.__name__,
                                            ('original_text', 'encrypted_text',
                                            'decipher_key', 'hash_value'),
                                            values=(text, _cipher_text,
                                                    _passkey.hex(), _hashed_text))
        if export_passkey:
            _file = Path(file_name)
            _parser = cls._new_parser()
            _encrypted_data = cls._new_template(cls,
                                                **encrypted_data._asdict(),
                                                iterations=_def_iterations
                                                )
            
            _parser.update(**_encrypted_data)
            if export_path:
                _file = Path(export_path) / _file
            cls._write2file(_file,
                            suffix=cls._Suffix._INI, mode='w',
                            parser=_parser, verbose=verbose)
        return encrypted_data


@dataclass(kw_only=True)
class DecipherEngine(_BaseEngine):
    """
    DecipherEngine is a class designed to decrypt data encrypted through the CipherEngine.
    
    This class specifically operates with configuration files generated by the CipherEngine during the encryption process.
    """
    __slots__ = ('__weakrefs__', '_passkey', 'passkey',
                '_iterations', 'file','text', 'passkey_file',
                'export_path', 'verbose', 'overwrite_file',
                '_salt')
    
    def __post_init__(self):
        super().__init__(passkey_file=self.passkey_file,
                        verbose=self.verbose,
                        overwrite_file=self.overwrite_file)
        self._get_dependencies()
    
    def _get_dependencies(self):
        """
        Internal method to fetch and parse necessary dependencies for the decryption process.
        """
        _config = self._validate_file(self.passkey_file)
        _parse = partial(self._parse_config, _config)
        self._iterations = int(_parse(section_key='iterations'))
        self._hash_val = _parse(section_key='hash_value')
        _mapper = lambda _sec_key: _parse(section='CIPHER_INFO', section_key=_sec_key)
        (self.text, self.file, self.passkey) = \
                map(_mapper, ('encrypted_text', 
                            'encrypted_file',
                            'decipher_key'))
    
    def decrypt_file(self) -> str:
        _config = self.passkey_file
        if not _config:
            raise CipherException(
                f'The specified configuration file {_config!r} is invalid. '
                'The decryption tool cannot proceed without the necessary dependencies.'
            )
        _config_path = self._validate_object(_config, type_is=Path)
        _cls_name = self.__class__.__name__.upper()
        _cipher_info = 'CIPHER_INFO'
        _security_par = 'SECURITY_PARAMS'
        _print = partial(self._print_header,
                        _cls_name,
                        with_iterations=False,
                        encrypting=False)
        _print(activated=True)
        
        _CEerror = self._log_verbose
        _suffix = self._Suffix._DEC
        _mem_info = self._find_mem_loc
        _log_sepr = '-'*self._MIN_CAPACITY
        _CEerror(_log_sepr)
        _CEerror(f'{_cls_name} decryption algorithm has begun. Gathering prerequisites...')
        
        _CEerror(f"Deriving security dependencies values from specified ({_config_path!r}) configuration file.")
        _config = self._validate_file(_config_path)
        _configp = partial(self._parse_config, _config)
        _init_iterations = self._iterations
        _hashed_value = _configp(section=_security_par, section_key='hash_value')
        _file = self._validate_file(self.file)
        _CEerror(f"{_cipher_info} dependencies ('encrypted_file', decipher_key) obtained.")
        _CEerror(f"{_security_par} dependencies ('iterations', 'hash_value', 'decipher_key') obtained.")
        
        _data = self._bytes_read(_file)
        _data_id = _mem_info(_data)
        _CEerror(f'File has been read in bytes mode and stored into memory location at ({_data_id}).')
        _identifier, \
            _identifier_len = self.identifier, len(self.identifier)
        
        _CEerror(f"Verifying that the file contains an encryption identifier that aligns with {_cls_name}'s identifier.")
        if _data.startswith(_identifier):
            _encrypted_data = _data[_identifier_len:]
            _CEerror('Identification found. Parsing files encrypted bytes.')
            _salt = _encrypted_data[:16]
            _iv = _encrypted_data[16:32]
            _cipher_text = _encrypted_data[32:]
            _kdf = self._get_pbk(_salt, iterations=_init_iterations)
            _kdf_name = _kdf.__class__.__name__.upper()
            _key = _kdf.derive(self.passkey.encode())
            _CEerror(f'Derived key from {_kdf_name}. Initializing decryption tool.')
            try:
                _CEerror('Fetching decryptor...')
                _cipher = self._get_cipher(_key, _iv)
            except ValueError as v_error:
                _v_name = v_error.__class__.__name__.upper()
                raise CipherException(
                        f'An error occurred while attempting to decrypt {_file.name!r}. '
                        f'Please ensure the file is already encrypted.\n[{_v_name}] {v_error}'
                        )
            
            _decryptor = _cipher.decryptor()
            _decrypted = _decryptor.update(_cipher_text) + _decryptor.finalize()
            _decrypted_id = _mem_info(_decrypted)
            _CEerror(
                f'Decrypting stored bytes at memory location ({_decrypted_id}).'
                )
            _CEerror('Writing decrypted data to file.')
            if self.overwrite_file:
                _CEerror(f'Overwriting {_file}')
                _suffix = _file.name.split('.')[-1]
                _decrypted_file = _file.as_posix()
                os.remove(_file)
            else:
                if _file.is_file():
                    _prefix = self._Suffix._PRE_DEC
                    _name = _file.stem.removeprefix(_prefix)
                    if re.search(r'\.', _name):
                        _name = _file.stem.split('.')[0]
                    _decrypted_file = (_file.parent / f'{_prefix}_{_name}').as_posix()
            
            _decrypted_file = Path(_decrypted_file)
            self._write2file(_decrypted_file,
                            suffix=_suffix, mode='wb',
                            data=_decrypted, reason='decrypted',
                            verbose=self.verbose)
            
            _CEerror('Verifying the hash value against the decrypted file for validation.')
            _check_decrypted = self._calc_file_hash(_decrypted_file.with_suffix('.'+_suffix))
            if (_check_decrypted != _hashed_value):
                self._failed_hash(_hashed_value, _check_decrypted)
            
            _CEerror('The matching hashed values affirm that no data loss occurred during the decryption process.')
            _CEerror(f'{_cls_name} decryption algorithm is now finished without encountering any errors for {_file}.')
            _print(activated=False, with_iterations=False)
            return
        else:
            raise CipherException(
                f'The file {_file!r} lacks the required identifier. '
                f"\n{_cls_name}'s decryption algorithm only operates with files containing its designated identifier. "
                f'\nEncryption algorithms identifier:\n{_identifier}')
    
    def decrypt_text(self) -> str:
        _org_hash = self._hash_val
        _passkey = base64.urlsafe_b64decode(self.passkey)
        _cipher = self._new_fernet(_passkey)
        _encrypted_bytes = base64.urlsafe_b64decode(self.text)
        _decrypted = _cipher.decrypt(_encrypted_bytes).decode('utf-8')
        _decrypted_hash = self._calc_str_hash(_decrypted)
        if _org_hash != _decrypted_hash:
            self._failed_hash(_org_hash, _decrypted_hash)
        return _decrypted
    
    @classmethod
    def quick_decrypt(cls, *,
                        encrypted_tuple: NamedTuple=None,
                        text: str=None,
                        passkey: Any=None,
                        hash_value: str=None) -> str:
        
        if encrypted_tuple:
            text, passkey, hash_value = \
                (map(partial(getattr, encrypted_tuple), ('encrypted_text',
                                                        'decipher_key',
                                                        'hash_value')))
        _hbytes = bytes.fromhex
        _cipher = cls._new_fernet(_hbytes(passkey))
        _encrypted_bytes = _hbytes(text)
        _decrypted = _cipher.decrypt(_encrypted_bytes).decode()
        _decrypted_hash = cls._calc_str_hash(cls, _decrypted)
        if hash_value and (_decrypted_hash != hash_value):
            cls._failed_hash(hash_value, _decrypted_hash)
        return _decrypted


def quick_encrypt_text(**kwargs):
    """
    Quickly encrypts text data and exports necessary information.

    Parameters:
    - text: Any: The text to be encrypted.
    - file_name: str: The name of the output file containing encryption details (default: 'ciphertext_info').
    - export_passkey: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
    - export_path: Any | None: The path to export the output file (default: None).
    - verbose: bool: Flag indicating whether to print verbose messages (default: False).

    Returns:
    - NamedTuple: Tuple containing information about the encryption process.

    Example:
    >>> result = quick_encrypt_text(text='Hello, World!')
    >>> print(result.encrypted_text)
    "abcdef1234567890..."
    """
    return CipherEngine.quick_encrypt(**kwargs)

def quick_decrypt_text(**kwargs):
    """
    Quickly decrypts text data using provided details.

    Parameters:
    - encrypted_tuple: NamedTuple: The NamedTuple class generated from the quick encryption process.
    - text: Any: The encrypted text to be decrypted.
    - passkey: Any: The decryption passphrase or key.
    - hash_value: Any | None: The hash value of the original data.

    Returns:
    - str: Decrypted text.

    Example:
    >>> result = quick_decrypt_text(text='abcdef1234567890...', passkey='my_secret_key', hash_value='...')
    >>> print(result)
    "Hello, World!"
    """
    return DecipherEngine.quick_decrypt(**kwargs)

def encrypt_text(**kwargs) -> NamedTuple:
    """
    Encrypts a specified text and exports necessary information.

    Parameters:
    - text: str: The text to be encrypted.
    - file_name: str: The name of the output file containing encryption details (default: 'info').
    - passkey: str | int | None: The passphrase or key for encryption (default: None).
    - export_passkey: bool: Flag indicating whether to export the passphrase to a separate file (default: True).
    - export_path: Any | None: The path to export the output file (default: None).

    Returns:
    - NamedTuple: Tuple containing information about the encryption process.
    
    Example:
    >>> result = encrypt_text(text='Hello, World!')
    >>> print(result.encrypted_text)
    "abcdef1234567890..."
    """
    return CipherEngine(**kwargs).encrypt_text()

def decrypt_text(**kwargs) -> str:
    """
    Decrypts a specified text using encryption details from the provided configuration file.
    
    ### Parameters:
    - passkey_file: str | Path: The path to the file containing the encryption details.
    - export_path: str | Path: The path to export the output file (default: None).
    - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).
    
    Returns:
    - str: Decrypted text.
    
    Example:
    >>> result = decrypt_text(passkey_file='ciphertext_info', export_path='decrypted')
    >>> print(result)
    "Hello, World!"
    """
    return DecipherEngine(**kwargs).decrypt_text()

def encrypt_file(**kwargs) -> NamedTuple:
    """
    Encrypts a specified file and exports necessary information.
    
    Parameters:
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
    
    Returns:
    - NamedTuple: Tuple containing information about the encryption process.
    
    Example:
    >>> result = encrypt_file(file='example.txt', passkey='my_secret_key', iterations=1000)
    >>> print(result.encrypted_file)
    "/path/to/encrypted_file.aes"
    """
    return CipherEngine(**kwargs).encrypt_file()

def decrypt_file(**kwargs) -> str:
    """
    Decrypts a specified file using encryption details stored in the provided configuration file \
    generated during the encryption process.

    Parameters:
    - passkey_file: str | Path: The path to the file containing the encryption details.
    - overwrite_file: bool | None: Flag indicating whether to overwrite the original file during decryption (default: False).
    - verbose: bool | None: Flag indicating whether to print verbose messages (default: False).

    Returns:
    - str: Path to the decrypted file.

    Example:
    >>> result = decrypt_file(passkey_file='ciphertext_info', overwrite_file=True)
    >>> print(result)
    "/path/to/decrypted_file.txt"
    """
    return DecipherEngine(**kwargs).decrypt_file()