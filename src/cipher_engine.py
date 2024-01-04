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
from datetime import datetime
from functools import partial, wraps
from random import SystemRandom
from itertools import cycle, islice
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from collections import OrderedDict, namedtuple
from string import digits, punctuation, ascii_letters
from typing import (Any, AnyStr, Dict,
                    Iterable, NamedTuple,
                    TypeVar, Optional, Union)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ('encrypt_file', 'decrypt_file',
            'encrypt_text', 'decrypt_text',
            'quick_ciphertext', 'quick_deciphertext')

B = TypeVar('B', bool, None)
I = TypeVar('I', int, None)
P = TypeVar('P', str, Path)

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
    def _get_clock_speed(cls) -> NamedTuple:
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
    def _sig_larger(cls, *args) -> NamedTuple:
        '''Significant difference between key_length and max_tokens'''
        valid_args = all((isinstance(arg, (int, float)) for arg in args))
        threshold = cls._MAX_TOKENS
        if len(args) == 2 and valid_args:
            Sig = namedtuple('SigLarger', ('status', 'threshold'))
            *args, = map(_BaseEngine._validate_object, args)
            abs_diff = abs(args[1] - args[0])
            status = (abs_diff >= threshold)
            return Sig(status, min(max(args), threshold))
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
        
        if all((min_power, max_power)):
            max_power = False
        
        base_power_range = np.arange(self.min_cores, self._MIN_CAPACITY, 0.1 if max_power else 0.01)
        base_power = base_power_range[self.max_cores - 1] * self._MIN_CAPACITY
        cpu_counts = np.arange(self.min_cores, self.max_cores + 1)
        cpu_powers = np.multiply(base_power, cpu_counts, order='C', subok=True).astype('int64')
        cpu_chart = OrderedDict(zip(cpu_counts, cpu_powers))
        
        if return_dict:
            return cpu_chart
        
        total_power = cpu_chart[self.min_cores + min((self.min_cores % 10,
                                                    self.max_cores % 10))]
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
        if self.default_cpu_count > self._MAX_CORES:
            self._MAX_CORES = self.default_cpu_count
        return self._MAX_CORES
    
    @property
    def min_cores(self):
        if self.default_cpu_count < self._MIN_CORES:
            self._MIN_CORES = self.default_cpu_count
        return self._MIN_CORES


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
        str_val = str(value).lower()
        val_mapper = {'true': True, 'false': False, 'none': None}
        return val_mapper.get(str_val, value)


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
    file: Optional[P] = field(repr=False, default=None)
    text: Optional[P] = field(repr=False, default=None)
    passkey_file: Optional[P] = field(repr=False, default=None)
    export_path: Optional[P] = field(repr=False, default=None)
    verbose: Optional[B] = field(repr=False, default=False)
    overwrite_file: Optional[B] = field(repr=False, default=False)
    
    _BACKEND = default_backend()
    _ALL_CHARS = (digits + punctuation + ascii_letters)
    _MIN_KEYLENGTH = _MIN_PBKLEN = 32
    _MAX_KEYLENGTH = _BasePower._MAX_CAPACITY
    
    @property
    def _identifier(self):
        return f'-----BEGIN CIPHERENGINE AES ENCRYPTED KEY-----'.encode()
    
    @staticmethod
    def _new_parser() -> ConfigParser:
        return ConfigParser()
    
    def _log_verbose(self, __msg, lg_method=logger.info):
        if self.verbose:
            CipherException(__msg, log_method=lg_method)
    
    @classmethod
    def _new_fernet(cls, __key):
        try:
            new_fernet = Fernet(__key, backend=cls._BACKEND)
        except ValueError:
            key = cls._base64_key(__key.encode())
            return cls._new_fernet(key)
        return new_fernet
    
    @staticmethod
    def _failed_hash(org_hash, second_hash):
        raise CipherException(
            'The discrepancy in hashed values points to a critical integrity issue, suggesting potential data loss. '
            'Immediate data investigation and remedial action are strongly advised. '
            f'\nOriginal Hash: {org_hash}'
            f'\nDecrypted Hash: {second_hash}'
        )
    
    @staticmethod
    def _get_cpu_power():
        return _BasePower().cpu_power
    
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
        if callable(self):
            cls_name = self.__name__
        else:
            cls_name = self.__class__.__name__
        
        repr_name = self._validate_object(__name, type_is=str) or cls_name
        term_size = self._terminal_size()
        iterations = self._iterations if isinstance(self._iterations, int) else self._get_cpu_power()
        if self.verbose:
            iter_str = f' (iterations={iterations:_})'
            header = '{} {} Tool {}{}'.format(
                                    repr_name,
                                    'decryption' if not encrypting else 'encryption',
                                    'activated' if activated else 'de-activated',
                                    iter_str if with_iterations else '').upper()
            color_code = '31' if not activated else '32'
            print(
            '\033[1;{}m{}\033[0m'.format(color_code, header.center(term_size, '*'), flush=True)
            )
    
    def _new_template(self, **kwargs) -> Dict:
        '''
        #### \
        This method creates a dynamic template incorporating encryption parameters and security details \
        suitable for writing encrypted data to a file. \
        The generated template can later be employed in the decryption process.
        '''
        hash_val = kwargs.pop(hash_str:=('hash_value'), None)
        iterations = kwargs.pop(iter_str:=('iterations'), self.cpu_power)
        return {'CIPHER_INFO': {**kwargs},
                'SECURITY_PARAMS':
                    {iter_str: iterations,
                    'algorithm': self._Suffix._AES.upper() + '-256',
                    'mode': self._Suffix._CFB,
                    hash_str: hash_val,
                    }
                }
    
    @staticmethod
    def _format_file(__file):
        time_now = datetime.now()
        formatted_time = time_now.strftime('%Y-%m-%dT%I-%M-%S%p-')
        return (__file.parent / formatted_time).as_posix() + (f'backup-{__file.name}')
    
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
                        num_attrs: int=5,
                        field_doc='Tuple containing dependecies for decryption purposes.'
                        ):
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
        module_name = module or typename
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
    
    @staticmethod
    def _terminal_size() -> int:
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
        check_str = cls._validate_object(__string, type_is=str)
        full_string = ''.join(check_str)
        string_filtered = full_string.translate(str.maketrans('', '', " \t\n\r\f\v" + exclude))
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
        except AttributeError as attr_error:
            raise CipherException(
                f'Failed to derive encoded bytes from {__key!r}. '
                f'\n{attr_error}'
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
        valid_text = self._validate_object(__text, type_is=str).encode()
        hash_ = hashlib.sha256()
        hash_.update(valid_text)
        return hash_.hexdigest()
    
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
        CEerror = CipherException
        possible_instances = (TypeError, ValueError, SyntaxError)
        
        if type_is is Any:
            type_is = type(__other)
        
        if type_is is int:
            try:
                _obj = int(str(__other))
            except possible_instances:
                raise CEerror(f'{arg!r} must be of type {int} or integer-like {str}')
        elif type_is is str:
            try:
                _obj = str(__other)
            except possible_instances:
                raise CEerror(f'{arg!r} must be of type {str}')
        elif type_is is list:
            try:
                _obj = list(map(str, __other))
            except possible_instances:
                raise CEerror(f'{arg!r} must be of type {list} with {int} or integer-like {str}')
        elif type_is is Path:
            try:
                _obj = Path(__other)
            except possible_instances:
                raise  CEerror(f'{arg!r} must be of type {Path} or {str}')
        else:
            return
        
        return _obj
    
    @classmethod
    def _generate_key(cls, *,
                    key_length: Union[int, str]=32,
                    exclude: Union[str, Iterable]='',
                    include_all: bool=False,
                    repeat: int=None):
        
        CEerror = CipherException
        _cpu_power = repeat or cls._get_cpu_power()
        if all((exclude, include_all)):
            raise CEerror("Cannot specify both 'exclude' and 'include_all' arguments.")
        _key_length = cls._validate_object(key_length, type_is=int, arg='key_length')
        _exclude = cls._validate_object(exclude, type_is=Any, arg='exlcude')
        _threshold = cls._sig_larger(_key_length, int(_cpu_power))
        
        if any((_key_length < cls._MIN_KEYLENGTH,
                _key_length > cls._MAX_KEYLENGTH)):
            raise CEerror(f'\'key_length\' must be of value {cls._MIN_KEYLENGTH} <= x <= {cls._MAX_KEYLENGTH}.')
        
        if any((cls._MAX_TOKENS >= cls._MAX_CAPACITY,
                _cpu_power >= cls._MAX_CAPACITY)):
            
            cls._capacity_error(f'Max Tokens: {cls._MAX_TOKENS}',
                                f'Character Repeat Count: {_cpu_power}')
        
        if not _threshold.status:
            cls._MAX_TOKENS = _threshold.threshold
            CEerror("The specified 'key_length' exceeds the number of characters that can be cycled during repetition."
                    f" Higher values for 'max_tokens' count is recommended for better results ('max_tokens' count is now {cls._MAX_TOKENS}).",
                    log_method=logger.warning)
        
        _slicer = lambda *args: ''.join(islice(*args, cls._MAX_TOKENS))
        _all_chars = _slicer(cycle(cls._ALL_CHARS))
        _chars = cls._filter_chars(_all_chars, exclude=punctuation)
        
        if include_all:
            _chars = _all_chars
        
        if exclude:
            _exclude = cls._exclude_type(exclude)
            if not _exclude:
                _chars = _chars
            elif _exclude:
                _chars = cls._filter_chars(_all_chars, exclude=_exclude)
        
        passkey = ''.join(SystemRandom().sample(
                        population=_chars,
                        k=min(_key_length, len(_chars))
                        ))
        return passkey
    
    @classmethod
    def _parse_config(cls, __config, *, section='SECURITY_PARAMS', section_key) -> Union[str, Any]:
        CEcritical = CipherException
        cparser = cls._new_parser()
        try:
            cparser.read(__config)
            sec_val = cparser[section].get(section_key)
        except configparser.NoSectionError:
            raise CEcritical(f"Confgiuration file does not contain section {section!r}")
        except configparser.NoOptionError:
            raise CEcritical(f"{section_key.capitalize()!r} was not found in {section!r} section."
                            f"\nIt is imperative that the values stored in the passkey configuration file generated by {cls.__name__.upper()} encryption algorithm tool is saved and not altered in anyway. "
                            "Failure to do so may alter the decryption process, potentially corrupting the files data.")
        except configparser.Error:
            raise CEcritical(f'An unexpected error occured trying to read {__config.name}.'
                            f'Decryption algorithm only works with its initial iterations value.')
        return sec_val
    
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
                    backend=cls._BACKEND
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
                backend=cls._BACKEND
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
            return all(char in cls._ALL_CHARS for char in __text)
        return False
    
    @staticmethod
    def _create_backup(__file: Union[str, Path]) -> None:
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
            log_method=logger.info
            )
            shutil.copy2(__file, formatted_bkp)
    
    @staticmethod
    def _write2file(__file: Path,
                    *,
                    suffix: bool='ini', data:AnyStr='',
                    mode: str='w', parser: configparser=None,
                    reason: str='', verbose: bool=False) -> None:
        
        CEerror = partial(CipherException, log_method=logger.info)
        new_file = Path(__file).with_suffix(f'.{suffix}')
        with open(new_file, mode=mode) as _file:
            if parser:
                parser.write(_file)
            else:
                _file.write(data)
            p_string = partial('{_file!r} has successfully been {reason} as {_path!r}'.format,
                        _file=_file.name, _path=_file)
            if verbose:
                CEerror(p_string(reason=reason or 'written'))
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
        valid_instances = (int, str, bool, bytes, Iterable)
        if any((not __k,
                not isinstance(__k, valid_instances),
                hasattr(__k, '__str__'))):
            __k = str(__k)
        
        defaults = map(re.escape, map(str, __defaults))
        pattern = '|'.join(defaults)
        esc_k = '|'.join(map(re.escape, __k))
        
        compiled = re.compile(pattern, re.IGNORECASE).search(esc_k)
        return bool(compiled)


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
    - quick_encrypt(): Quickly encrypts text data and exports necessary information on-the-go.

    Example:
    >>> cipher = CipherEngine(passkey='my_secret_key', iterations=1000)
    >>> cipher.encrypt_file()
    """
    __slots__ = ('__weakrefs__', '_iterations', '_passkey',
                'file', '_file', 'text', 'passkey_file',
                'export_path', 'verbose', 'overwrite_file',
                '_salt')
    
    passkey: Optional[Union[str, int]] = field(init=True, repr=False, default=None)
    key_length: Optional[I] = field(repr=True, default=_BaseEngine._MIN_KEYLENGTH)
    iterations: Optional[I] = field(repr=True, default=None)
    exclude_chars: Union[list, str] = field(repr=True, default=None)
    backup_file: Optional[B] = field(repr=False, default=True)
    export_passkey: Optional[B] = field(repr=False, default=True)
    include_all_chars: Optional[B] = field(repr=False, default=False)
    min_power: Optional[B] = field(repr=False, default=False)
    max_power: Optional[B] = field(repr=False, default=False)
    
    def __post_init__(self):
        """
        Perform post-initialization tasks including validating and deriving encryption parameters.
        """
        super().__init__(file=self.file,
                        overwrite_file=self.overwrite_file,
                        verbose=self.verbose,
                        text=self.text)
        
        self._iterations = self._calculate_iterations()
        self.passkey = self._validate_passkey(self.passkey,
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
        if self.iterations:
            _iter_count = self._validate_object(self.iterations, type_is=int, arg='iterations')
            if _iter_count >= self._MAX_CAPACITY:
                return self._capacity_error(f'Specified value: {_iter_count}',
                                            f'Max Iterations value: {self._MAX_CAPACITY}')
            return _iter_count
        
        _power_class = partial(self._create_subclass,
                            'PStats', ('min', 'max'),
                            field_doc='Minimum and maximum values for number of iterations.')
        args = (self.min_power, self.max_power)
        if any(args):
            power_info = _power_class(values=args)
            return self.calculate_cpu(
                            min_power=power_info.min,
                            max_power=power_info.max
                            )
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
        if any((not __passkey,
                not cls._char_checker(__passkey))):
            __passkey = cls._generate_key(**kwargs)
        
        return __passkey
    
    def encrypt_file(self) -> NamedTuple:
        cls_name = self.__class__.__name__.upper()
        self._print_header(cls_name)
        _file = self._validate_file(self.file)
        
        CEinfo = self._log_verbose
        log_sepr = 'ENCRYPTION-SECTION'.center(115, '-')
        CEinfo(log_sepr)
        CEinfo(f'{cls_name} encryption algorithm has begun. Gathering prerequisites to encrypt {_file.name!r}...')
        CEinfo("Calculating files hash value as a saftey precaution to ensure data integrity when decrypting.")
        
        _hash_val = self._calc_file_hash(_file)
        _kdf = self._get_pbk(iterations=self._iterations)
        _pbk_name = _kdf.__class__.__name__
        
        CEinfo(f'Acquiring the salt value from {_pbk_name} to enhance the security of the cryptographic processes. '
                'This guarantees the uniqueness of each derived key, '
                'safeguarding against diverse rainbow table and brute-force attacks.')
        
        _salt = self._salt = _kdf._salt
        CEinfo(f'Successfully obtained the salt value from {_pbk_name}. '
                'The integrity of the cryptographic processes is now fortified.')
        CEinfo(f'Deriving the cryptographic key with iterations over {self._iterations} using {_pbk_name} '
                'and obtaining the resulting key for further security measures.')
        
        _key = _kdf.derive(self.passkey.encode())
        _iv = self._gen_random()
        fernet = self._get_cipher(_key, _iv)
        cipher_name = fernet.__class__.__name__.upper()
        CEinfo(f'Key successfully acquired. Preparing to read the specified file in bytes mode for encryption purposes '
                f'using cryptographic {cipher_name} encryptor.')
        encryptor = fernet.encryptor()
        
        CEinfo(f"Reading files unencrypted data in bytes mode to store into memory for encryption.")
        plain_text = self._bytes_read(_file)
        plain_id = self._find_mem_loc(plain_text)
        
        CEinfo(f"Ensuring the absence of {cls_name}'s encryption identifier "
                'to uphold its integrity by preventing any inadvertent or accidental re-encryption.')
        
        if plain_text.startswith(self._identifier):
            raise CipherException(
            f'{cls_name} encrypter identification detected signaling that the file {_file!r} is already encrypted. '
            '\nRe-encrypting it poses a significant risk of resulting in inaccurate decryption, potentially leading to irreversible data corruption. '
            '\nIt is crucial to decrypt the file before attempting any further encryption.'
            '\n\nStrictly limit the encryption process to once per file for each subsequent decryption to safeguard against catastrophic data loss.'
            )
        
        CEinfo('No encryption ID found. File is suitable for encryption.')
        CEinfo(f'Securely encrypting stored bytes located at memory address: ({plain_id})...')
        CEinfo('Encrypting stored bytes...')
        
        encrypted = encryptor.update(plain_text) + encryptor.finalize()
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
        encryption_data = (self._identifier + _salt + _iv + encrypted)
        self._write2file(encr_file,
                        suffix=default_suffix, mode='wb',
                        data=encryption_data, reason='exported',
                        verbose=self.verbose)
        
        _parser = self._new_parser()
        
        passkey_suffix = self._Suffix._INI
        passkey_name = Path(f'{encr_file.stem}_passkey').with_suffix(f'.{passkey_suffix}')
        passkey_file = new_path / passkey_name
        
        _write_func = partial(self._write2file,
                            passkey_file,
                            reason='exported')
        _write2file = partial(_write_func,
                            suffix=passkey_suffix,
                            parser=_parser,
                            verbose=self.verbose)
        passkey_tuple = self._create_subclass('Encrypter',
                                                ('original_file',
                                                'encrypted_file',
                                                'decipher_key', 'hash_value'),
                                                values=(_file.as_posix(),
                                                        encr_file.as_posix(),
                                                        self.passkey, _hash_val)
                                                )
        encr_data = self._new_template(**passkey_tuple._asdict())
        try:
            _parser.update(**encr_data)
        except ValueError:
            CEinfo(f'[PASSKEY ERROR] Special characters are not suitable for {ConfigParser.__name__!r} (.INI configurations). '
                    'Serializing as JSON (.json).',
                    lg_method=logger.warning)
            encr_data = JSONify(**encr_data).to_json(indent=4)
            passkey_suffix = self._Suffix._JSON
            _write2file = partial(_write_func,
                                suffix=passkey_suffix,
                                data=encr_data,
                                verbose=self.verbose)
        
        if self.export_passkey:
            _write2file()
        
        CEinfo(f'{cls_name} encryption algorithm is now finished without encountering any errors for {_file}. '
                f'Kindly utilize the cipher key stored in {passkey_file} to decrypt at anytime.')
        self._print_header(cls_name, activated=False, with_iterations=False)
        return passkey_tuple
    
    def encrypt_text(self) -> NamedTuple:
        _print_header = partial(self._print_header, 'CipherText')
        _print_header()
        
        org_text = self._validate_object(self.text, type_is=str)
        hashed_text = self._calc_str_hash(org_text)
        print(hashed_text)
        passphrase = self.passkey
        if not passphrase:
            passphrase = self._passkey
        
        _kdf = self._get_pbk(iterations=self._iterations)
        self._salt = base64.urlsafe_b64encode(_kdf._salt)
        passkey = self._base64_key(_kdf.derive(passphrase.encode()))
        fernet = self._new_fernet(passkey)
        cipher_text = fernet.encrypt(org_text.encode())
        _base64 = lambda _x: self._base64_key(_x).decode()
        encrypted_data = self._create_subclass(
                            self.__class__.__name__,
                            field_names=('original_text', 'encrypted_text',
                                        'decipher_key', 'hash_value'),
                            values=(org_text, _base64(cipher_text),
                                    _base64(passkey), hashed_text)
                            )
        
        if self.export_passkey:
            _file = Path('ciphertext_info')
            if self.export_path:
                _file = Path(self.export_path) / _file
            cparser = self._new_parser()
            _encrypted_data = self._new_template(**encrypted_data._asdict())
            cparser.update(**_encrypted_data)
            self._write2file(_file,
                            suffix=self._Suffix._INI, mode='w',
                            parser=cparser, verbose=self.verbose)
        _print_header(with_iterations=False, activated=False)
        return encrypted_data
    
    @classmethod
    def quick_encrypt(cls, *,
                        text,
                        passkey=None,
                        file_name='ciphertext_info',
                        export_passkey=True,
                        export_path=None) -> NamedTuple:
        
        cls._print_header(cls, 'Quick-CipherText')
        hashed_text = cls._calc_str_hash(cls, text)
        if not passkey:
            passkey = cls._base64_key(cls._generate_key(key_length=32).encode())
            fernet = cls._new_fernet(passkey)
        encrypted_bytes = fernet.encrypt(text.encode())
        cipher_text = encrypted_bytes.hex()
        encrypted_data = cls._create_subclass(cls.__name__,
                                            ('original_text', 'encrypted_text',
                                            'decipher_key', 'hash_value'),
                                            values=(text, cipher_text,
                                                    passkey.hex(), hashed_text))
        if export_passkey:
            _file = Path(file_name)
            cparser = cls._new_parser()
            _encrypted_data = cls._new_template(cls,
                                                **encrypted_data._asdict(),
                                                iterations=cls._get_cpu_power()
                                                )
            
            cparser.update(**_encrypted_data)
            if export_path:
                _file = Path(export_path) / _file
            cls._write2file(_file, suffix=cls._Suffix._INI,
                            mode='w', parser=cparser)
        cls._print_header(cls, 'CipherText', with_iterations=False, activated=False)
        return encrypted_data


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
                        overwrite_file=self.overwrite_file)
        if not callable(self):
            self._get_dependencies()
    
    def _get_dependencies(self):
        """
        Internal method to fetch and parse necessary dependencies for the decryption process.
        """
        passkey_file = self._validate_file(self.passkey_file)
        cparser_func = partial(self._parse_config, passkey_file)
        self._iterations = int(cparser_func(section_key='iterations'))
        self._hash_val = cparser_func(section_key='hash_value')
        sec_getter = lambda _sec_key: cparser_func(section='CIPHER_INFO', section_key=_sec_key)
        self.encrypted_text = sec_getter('encrypted_text')
        self.encrypted_file = sec_getter('encrypted_file')
        self.decipher_key = sec_getter('decipher_key')
    
    def decrypt_file(self) -> str:
        if not self.passkey_file:
            raise CipherException(
                f'The specified configuration file {self.passkey_file!r} is invalid. '
                'The decryption tool cannot proceed without the necessary dependencies.'
            )
        config_path = self._validate_object(self.passkey_file, type_is=Path)
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
        log_sepr = 'DECRYPTION-SECTION'.center(115, '-')
        CEerror(log_sepr)
        CEerror(f'{cls_name} decryption algorithm has begun. Gathering prerequisites...')
        
        CEerror(f"Deriving security dependencies values from specified ({config_path!r}) configuration file.")
        cipher_info = 'CIPHER_INFO'
        security_par = 'SECURITY_PARAMS'
        config_file = self._validate_file(config_path)
        cparser_func = partial(self._parse_config, config_file)
        hashed_value = cparser_func(section=security_par, section_key='hash_value')
        _file = self._validate_file(self.encrypted_file)
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
            _kdf = self._get_pbk(_salt, iterations=self._iterations)
            _kdf_name = _kdf.__class__.__name__.upper()
            _key = _kdf.derive(self.decipher_key.encode())
            CEerror(f'Derived key from {_kdf_name}. Initializing decryption tool.')
            try:
                CEerror('Fetching decryptor...')
                fernet = self._get_cipher(_key, _iv)
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
    
    def decrypt_text(self) -> str:
        print_header = partial(
                        self._print_header,
                        'DecipherText',
                        with_iterations=False,
                        encrypting=False
                        )
        print_header(activated=True)
        passkey = base64.urlsafe_b64decode(self.decipher_key)
        fernet = self._new_fernet(passkey)
        encrypted_bytes = base64.urlsafe_b64decode(self.encrypted_text)
        decrypted = fernet.decrypt(encrypted_bytes).decode('utf-8')
        decrypted_hash = self._calc_str_hash(decrypted)
        if self._hash_val != decrypted_hash:
            self._failed_hash(self._hash_val, decrypted_hash)
        print_header(activated=False)
        return decrypted
    
    @classmethod
    def quick_decrypt(cls,
                        *,
                        text: str=None,
                        decipher_key: Any=None,
                        hash_value: str=None,
                        encrypted_tuple: NamedTuple=None) -> str:
        print_header = partial(
                        cls._print_header,
                        cls,
                        'Quick-DecipherText',
                        with_iterations=False,
                        encrypting=False
                        )
        print_header(activated=True)
        
        if encrypted_tuple:
            text = encrypted_tuple.encrypted_text
            decipher_key = encrypted_tuple.decipher_key
            hash_value = encrypted_tuple.hash_value
        
        fernet = cls._new_fernet(bytes.fromhex(decipher_key))
        encrypted_bytes = bytes.fromhex(text)
        decrypted = fernet.decrypt(encrypted_bytes).decode()
        decrypted_hash = cls._calc_str_hash(cls, decrypted)
        if hash_value and (decrypted_hash != hash_value):
            cls._failed_hash(hash_value, decrypted_hash)
        print_header(activated=False)
        return decrypted

def generate_cipher_key(**kwargs):
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
        - repeat (int): The number of iterations for character cycling. Defaults to None.
        
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
        - encrypted_tuple: NamedTuple: The NamedTuple class generated from the quick encryption process.
        - text: Any: The encrypted text to be decrypted.
        - decipher_key: Any: The decryption passphrase or key.
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
        - file_name: str: The name of the output file containing encryption details (default: 'info').
        - passkey: str | int | None: The passphrase or key for encryption (default: None).
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

def decrypt_text(**kwargs) -> str:
    """
    ### Decrypts a specified file using encryption details stored in the provided configuration file \
        generated during the encryption process.
    
    ### Parameters:
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
