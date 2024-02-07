<<<<<<< HEAD
usage: cipher_engine.py [-h] [--source] [--doc] [--change-log] [--tests]
                        {generate_key,encrypt_text,decrypt_text,encrypt_file,decrypt_file}
                        ...

Command-line interface designed for the management of cryptographic keys, along with the
capabilities for encrypting/decrypting both text and files.
=======
usage: cipher_engine.py [-h] [--source] [--doc] [--readme] [--change-log]
                        [--tests] [--version] [--author] [--copyright]
                        [--summary] [--url] [--license] [--full-license]
                        {generate_key,encrypt_text,decrypt_text,encrypt_file,decrypt_file}
                        ...

Command-line interface designed for the management of cryptographic keys, along
with the capabilities for encrypting/decrypting both text and files.
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2

positional arguments:
  {generate_key,encrypt_text,decrypt_text,encrypt_file,decrypt_file}
                        All Command Options.
    generate_key        Generate a secure cryptographic key.
    encrypt_text        Encrypt any text with customizable parameters
    decrypt_text        Decrypt the given text.
    encrypt_file        Encrypt a file with customizable parameters.
    decrypt_file        The file to be decrypted.

options:
  -h, --help            show this help message and exit
  --source              Display source code.
  --doc                 Display documentation.
<<<<<<< HEAD
  --change-log          Display change-log.
  --tests               Display engine pytests.
usage: cipher_engine.py generate_key [-h] [--gd] [-l LENGTH] [-a] [-b] [-s REPEAT]
                                     [-e EXCLUDE_CHARS] [-se SAFE_ENCODING]
=======
  --readme              Display README.
  --change-log          Display CHANGELOG.
  --tests               Display engine pytests.
  --version             Display current version.
  --author              Display the primary author.
  --copyright           Display copyright.
  --summary             Display summary.
  --url                 Display GitHub url.
  --license             Display license.
  --full-license        Display full license.
usage: cipher_engine.py generate_key [-h] [--gd] [-l LENGTH] [-a] [-b]
                                     [-s REPEAT] [-e EXCLUDE_CHARS]
                                     [-se SAFE_ENCODING]
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2

options:
  -h, --help            show this help message and exit
  --gd                  Display documentation.
  -l LENGTH, --length LENGTH
                        Specify the length of the cryptographic key.
<<<<<<< HEAD
  -a, --all-chars       Include all available characters in the cryptographic key.
  -b, --bypass-length   Bypass restrictions for cryptographic key length.
  -s REPEAT, --repeat REPEAT
                        Specify the repeat count for characters to be cycled through
                        (Not needed).
=======
  -a, --all-chars       Include all available characters in the cryptographic
                        key.
  -b, --bypass-length   Bypass restrictions for cryptographic key length.
  -s REPEAT, --repeat REPEAT
                        Specify the repeat count for characters to be cycled
                        through (Not needed).
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2
  -e EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Specify characters to exclude from the cryptographic key.
  -se SAFE_ENCODING, --safe-encoding SAFE_ENCODING
                        Applies URL-safe Base64 encoding to the passkey
<<<<<<< HEAD
usage: cipher_engine.py encrypt_text [-h] [-t TEXT] [-n NUM_KEYS] [-ec EXCLUDE_CHARS]
                                     [--all-chars] [-fn FILE_NAME] [-s SERIALIZER]
                                     [--special-keys] [-ep EXPORT_PATH] [-i IDENTIFIERS]
                                     [--export-passkey] [--etd]
=======
usage: cipher_engine.py encrypt_text [-h] [-t TEXT] [-n NUM_KEYS]
                                     [-ec EXCLUDE_CHARS] [--all-chars]
                                     [-fn FILE_NAME] [-s SERIALIZER]
                                     [--special-keys] [-ep EXPORT_PATH]
                                     [-i IDENTIFIERS] [--export-passkey] [--etd]
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2

options:
  -h, --help            show this help message and exit
  -t TEXT, --text TEXT  The text to be encrypted.
  -n NUM_KEYS, --num-keys NUM_KEYS
<<<<<<< HEAD
                        The number of cryptographic keys to be generated and processed
                        with for encryption.
  -ec EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Characters to exclude during passphrase generation
  --all-chars           Include all available characters in the cryptographic key.
  -fn FILE_NAME, --file-name FILE_NAME
                        The name of the file containing the encryption details.
  -s SERIALIZER, --serializer SERIALIZER
                        The type of serialization to be used for exporting the passkey
                        file.
  --special-keys        Enables CipherEngine's custom cryptographic key generation.
  -ep EXPORT_PATH, --export-path EXPORT_PATH
                        The path for the passkey configuration file to be exported too.
  -i IDENTIFIERS, --identifiers IDENTIFIERS
                        Specifiy a custom encryption identifier for the start and end of
                        the encryption key
=======
                        The number of cryptographic keys to be generated and
                        processed with for encryption.
  -ec EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Characters to exclude during passphrase generation
  --all-chars           Include all available characters in the cryptographic
                        key.
  -fn FILE_NAME, --file-name FILE_NAME
                        The name of the file containing the encryption details.
  -s SERIALIZER, --serializer SERIALIZER
                        The type of serialization to be used for exporting the
                        passkey file.
  --special-keys        Enables CipherEngine's custom cryptographic key
                        generation.
  -ep EXPORT_PATH, --export-path EXPORT_PATH
                        The path for the passkey configuration file to be
                        exported too.
  -i IDENTIFIERS, --identifiers IDENTIFIERS
                        Specifiy a custom encryption identifier for the start and
                        end of the encryption key
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2
  --export-passkey      Exports passkey configuration file.
  --etd                 Display documentation.
usage: cipher_engine.py decrypt_text [-h] [-pf PASSKEY_FILE] [--dtd]

options:
  -h, --help            show this help message and exit
  -pf PASSKEY_FILE, --passkey-file PASSKEY_FILE
                        The path of the passkey configuration file.
  --dtd                 Display documentation.
usage: cipher_engine.py encrypt_file [-h] [-f FILE] [-n NUM_KEYS] [-fn FILE_NAME]
<<<<<<< HEAD
                                     [-ec EXCLUDE_CHARS] [-ep EXPORT_PATH] [-b] [-o]
                                     [-e EXPORT_PASSKEY] [-a ALL_CHARS] [-i IDENTIFIERS]
                                     [--efd] [--special-keys]
=======
                                     [-ec EXCLUDE_CHARS] [-ep EXPORT_PATH] [-b]
                                     [-o] [-e EXPORT_PASSKEY] [-a ALL_CHARS]
                                     [-i IDENTIFIERS] [--efd] [--special-keys]
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The file to be encrypted.
  -n NUM_KEYS, --num-keys NUM_KEYS
<<<<<<< HEAD
                        The number of cryptographic keys to be generated and processed
                        with for encryption.
=======
                        The number of cryptographic keys to be generated and
                        processed with for encryption.
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2
  -fn FILE_NAME, --file-name FILE_NAME
                        The name of the file containing the encryption details.
  -ec EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Characters to exclude during passphrase generation
  -ep EXPORT_PATH, --export-path EXPORT_PATH
                        The path where exported files will be stored.
  -b, --backup          Backup original file.
  -o, --overwrite       Overwrite the original file into an encrypted file.
  -e EXPORT_PASSKEY, --export-passkey EXPORT_PASSKEY
                        Exports passkey configuration file.
  -a ALL_CHARS, --all-chars ALL_CHARS
<<<<<<< HEAD
                        Include all available characters in the cryptographic key.
  -i IDENTIFIERS, --identifiers IDENTIFIERS
                        Specifiy a custom encryption identifier for the start and end of
                        the encryption key
  --efd                 Display documentation.
  --special-keys        Enables CipherEngine's custom cryptographic key generation.
=======
                        Include all available characters in the cryptographic
                        key.
  -i IDENTIFIERS, --identifiers IDENTIFIERS
                        Specifiy a custom encryption identifier for the start and
                        end of the encryption key
  --efd                 Display documentation.
  --special-keys        Enables CipherEngine's custom cryptographic key
                        generation.
>>>>>>> c8a4519ed95e04889334dcc0f85290b7f1e87bc2
usage: cipher_engine.py decrypt_file [-h] [-pf PASSKEY_FILE] [-o] [--dfd]

options:
  -h, --help            show this help message and exit
  -pf PASSKEY_FILE, --passkey-file PASSKEY_FILE
                        The path of the passkey configuration file.
  -o, --overwrite       Overwrite the original file into an encrypted file.
  --dfd                 Display documentation.
