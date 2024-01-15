usage: cipher_engine.py [-h] [-s] [-d] [-c]
                        {generate_key,quick_encrypt_text,quick_decrypt_text,encrypt_text,decrypt_text,encrypt_file,decrypt_file}
                        ...

Command-line interface designed for the management of cryptographic keys, along with the capabilities
for encrypting/decrypting both text and files, featuring quick cipher methods.

positional arguments:
  {generate_key,quick_encrypt_text,quick_decrypt_text,encrypt_text,decrypt_text,encrypt_file,decrypt_file}
                        All Command Options.
    generate_key        Generate a secure cryptographic key.
    quick_encrypt_text  Quickly encrypt text with ease.
    quick_decrypt_text  Quickly decrypt text with ease.
    encrypt_text        Encrypt any text with customizable parameters
    decrypt_text        Decrypt the given text.
    encrypt_file        Encrypt any files with customizable parameters.
    decrypt_file        The file to be decrypted.

options:
  -h, --help            show this help message and exit
  -s, --source          Display source code.
  -d, --doc             Display documentation.
  -c, --change-log      Display change-log.
usage: cipher_engine.py generate_key [-h] [--gd] [-l LENGTH] [-a] [-b] [-s REPEAT] [-e EXCLUDE_CHARS]

options:
  -h, --help            show this help message and exit
  --gd                  Display documentation.
  -l LENGTH, --length LENGTH
                        Specify the length of the cryptographic key.
  -a, --all-chars       Include all available characters in the cryptographic key.
  -b, --bypass-length   Bypass restrictions for cryptographic key length.
  -s REPEAT, --repeat REPEAT
                        Specify the repeat count for characters to be cycled through (Not needed).
  -e EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Specify characters to exclude from the cryptographic key.
usage: cipher_engine.py quick_encrypt_text [-h] [-t TEXT] [-f FILE_NAME] [-e] [-p EXPORT_PATH] [--qetd]

options:
  -h, --help            show this help message and exit
  -t TEXT, --text TEXT  The text to be encrypted
  -f FILE_NAME, --file-name FILE_NAME
                        The file name of the passkey configuration file.
  -e, --export-passkey  Exports passkey configuration file.
  -p EXPORT_PATH, --export-path EXPORT_PATH
                        The path for the passkey configuration file to be exported too.
  --qetd                Display documentation.
usage: cipher_engine.py quick_decrypt_text [-h] [-t TEXT] [-k KEY] [-hv HASH_VALUE] [--qdtd]

options:
  -h, --help            show this help message and exit
  -t TEXT, --text TEXT  The text to be decrypted.
  -k KEY, --key KEY     The decipher key to decrypt the given text.
  -hv HASH_VALUE, --hash-value HASH_VALUE
                        Provide the original hash value for integrity validation.
  --qdtd                Display documentation.
usage: cipher_engine.py encrypt_text [-h] [-t TEXT] [-l KEY_LENGTH] [-pf PASSKEY_FILE] [-i ITERATIONS]
                                     [-ec EXCLUDE_CHARS] [-a ALL_CHARS] [-ep EXPORT_PATH] [-e] [-v]
                                     [--etd] [-bl]

options:
  -h, --help            show this help message and exit
  -t TEXT, --text TEXT  The text to be encrypted.
  -l KEY_LENGTH, --key-length KEY_LENGTH
                        The length of the cryptographic key.
  -pf PASSKEY_FILE, --passkey-file PASSKEY_FILE
                        The path of the passkey configuration file.
  -i ITERATIONS, --iterations ITERATIONS
                        The number of iterations for key derivation
  -ec EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Characters to exclude during passphrase generation
  -a ALL_CHARS, --all-chars ALL_CHARS
                        Include all available characters in the cryptographic key.
  -ep EXPORT_PATH, --export-path EXPORT_PATH
                        The path for the passkey configuration file to be exported too.
  -e, --export-passkey  Exports passkey configuration file.
  -v, --verbose         Show verbose details.
  --etd                 Display documentation.
  -bl, --bypass-length  Bypass restrictions for cryptographic key length.
usage: cipher_engine.py decrypt_text [-h] [-pf PASSKEY_FILE] [--dtd] [-v]

options:
  -h, --help            show this help message and exit
  -pf PASSKEY_FILE, --passkey-file PASSKEY_FILE
                        The path of the passkey configuration file.
  --dtd                 Display documentation.
  -v, --verbose         Show verbose details.
usage: cipher_engine.py encrypt_file [-h] [-f FILE] [-k PASSKEY] [-l KEY_LENGTH] [-i ITERATIONS]
                                     [-ec EXCLUDE_CHARS] [-b] [-o] [-bl] [-e EXPORT_PASSKEY]
                                     [-a ALL_CHARS] [-v] [-mn] [-mx] [--efd]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The file to be encrypted.
  -k PASSKEY, --passkey PASSKEY
                        The passkye to be used to decrypt the file.
  -l KEY_LENGTH, --key-length KEY_LENGTH
                        The length of the cryptographic key.
  -i ITERATIONS, --iterations ITERATIONS
                        The number of iterations for key derivation
  -ec EXCLUDE_CHARS, --exclude-chars EXCLUDE_CHARS
                        Characters to exclude during passphrase generation
  -b, --backup          Backup original file.
  -o, --overwrite       Overwrite the original file into an encrypted file.
  -bl, --bypass-length  Bypass restrictions for cryptographic key length.
  -e EXPORT_PASSKEY, --export-passkey EXPORT_PASSKEY
                        Exports passkey configuration file.
  -a ALL_CHARS, --all-chars ALL_CHARS
                        Include all available characters in the cryptographic key.
  -v, --verbose         Show verbose details.
  -mn, --min-power      Sets number of iterations to a low computational power usage based on CPU
                        cores.
  -mx, --max-power      Sets number of iterations to a high computational power usage based on CPU
                        cores.
  --efd                 Display documentation.
usage: cipher_engine.py decrypt_file [-h] [-pf PASSKEY_FILE] [-o] [-v] [--dfd]

options:
  -h, --help            show this help message and exit
  -pf PASSKEY_FILE, --passkey-file PASSKEY_FILE
                        The path of the passkey configuration file.
  -o, --overwrite       Overwrite the original file into an encrypted file.
  -v, --verbose         Show verbose details.
  --dfd                 Display documentation.
