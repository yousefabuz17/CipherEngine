import sys
from pathlib import Path
from functools import partial
from argparse import ArgumentParser

from cipher_engine import *


MAIN_DIR = Path(__file__).parents[2].resolve()
read_file = partial(CipherEngine._read_file, mode="r")


def load_documents():
    documents = dict.fromkeys(
        (
            "README.md",
            "CHANGELOG.md",
            "CLI-OPTIONS.md",
            "LICENSE.md",
            "src/cipher_engine/cipher_engine.py",
            "tests/test_cipher.py",
        )
    )
    valid_files = filter(
        lambda x: x[1],
        CipherEngine._EXECUTOR.map(lambda fp: (fp, Path(fp).is_file()), documents),
    )
    for fp, _isfile in valid_files:
        documents.pop(fp)
        documents[Path(fp).stem] = read_file(MAIN_DIR / fp)
    return documents


METADATA.update(**load_documents())


def cli_parser():
    arg_parser = ArgumentParser(
        description="Command-line interface designed for the management of cryptographic keys, \
            along with the capabilities for encrypting/decrypting both text and files."
    )

    # XXX Main Subparser
    subparsers = arg_parser.add_subparsers(dest="command", help="All Command Options.")

    # XXX Main Options (documentation, CHANGELOG and source code)
    arg_parser.add_argument(
        "--source", action="store_true", help="Display source code."
    )
    arg_parser.add_argument("--doc", action="store_true", help="Display documentation.")
    arg_parser.add_argument("--readme", action="store_true", help="Display README.")
    arg_parser.add_argument(
        "--change-log", action="store_true", help="Display CHANGELOG."
    )
    arg_parser.add_argument(
        "--tests", action="store_true", help="Display engine pytests."
    )
    arg_parser.add_argument(
        "--version", action="store_true", help="Display current version."
    )
    arg_parser.add_argument(
        "--author", action="store_true", help="Display the primary author."
    )
    arg_parser.add_argument(
        "--copyright", action="store_true", help="Display copyright."
    )
    arg_parser.add_argument("--summary", action="store_true", help="Display summary.")
    arg_parser.add_argument("--url", action="store_true", help="Display GitHub url.")
    arg_parser.add_argument("--license", action="store_true", help="Display license.")
    arg_parser.add_argument(
        "--full-license", action="store_true", help="Display full license."
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

    if args.source:
        print(METADATA["cipher_engine"])
    elif args.readme:
        print(METADATA["README"])
    elif args.doc:
        print(METADATA["doc"])
    elif args.change_log:
        print(METADATA["CHANGELOG"])
    elif args.tests:
        print(METADATA["test_cipher"])
    elif args.version:
        print(METADATA["version"])
    elif args.author:
        print(METADATA["author"])
    elif args.copyright:
        print(METADATA["copyright"])
    elif args.summary:
        print(METADATA["summary"])
    elif args.url:
        print(METADATA["url"])
    elif args.license:
        print(METADATA["license"])
    elif args.full_license:
        print(METADATA["LICENSE"])
    elif args.command == "generate_key":
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
    else:
        cli_doc = METADATA[cli_str:="CLI-OPTIONS"]
        if not cli_doc:
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
                cli_doc = (MAIN_DIR / cli_str).with_suffix(".md")
                aparser.print_help(
                    file=open(
                        cli_doc, mode="a", encoding="utf-8", errors="ignore"
                    )
                )
            print(read_file(cli_doc))
        elif len(cli_doc) >= 1:
            print(cli_doc)
        else:
            sys.exit(0)


__all__ = "cli_interface"
