#!/usr/bin/env python
#
# File Cryptography functions for config file for SASECLI.
# File format inspired by Ansible Vault.
#

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
from getpass import getpass
from . import __version__
from .defaults import DEFAULT_YAML_WITH_COMMENTS
import argparse
import base64
import os
import sys
import pathlib
import tempfile
import shutil

VERSION_BYTES = __version__.encode('utf-8')
ENCRYPTEDHEADER = b"$sasecli:2.0:"
ENCRYPTEDHEADER_LEN = len(ENCRYPTEDHEADER)
CONFIGHEADER_UNIX = b"---\ntype: sasecli\nversion: " + VERSION_BYTES + b"\n"
CONFIGHEADER_WINDOWS = b"---\r\ntype: sasecli\r\nversion: " + VERSION_BYTES + b"\r\n"
CONFIG_DIR = '.sasecli'
CONFIG_YAML = 'config.yml'
WINDOWS_LINE_ENDING = b'\r\n'
UNIX_LINE_ENDING = b'\n'

# Set default editors
if sys.platform == "win32":
    SYSTEM_TYPE = "WINDOWS"
    DIRSLASH = '\\'
    DEFAULT_EDITOR = 'start "sasecli_edit_config" /B /WAIT "{0}" "{1}"'
    DEFAULT_EDITOR_BINARY = 'notepad.exe'
    LINE_ENDING = WINDOWS_LINE_ENDING
    # Make sure Windows default YAML is CRLF
    DEFAULT_YAML_WITH_COMMENTS = DEFAULT_YAML_WITH_COMMENTS.replace(UNIX_LINE_ENDING, WINDOWS_LINE_ENDING)
    CONFIGHEADER = CONFIGHEADER_WINDOWS
    CONFIGHEADER_SIZE = len(CONFIGHEADER)

else:
    SYSTEM_TYPE = "UNIX"
    DIRSLASH = '/'
    DEFAULT_EDITOR = '"{0}" "{1}"'
    DEFAULT_EDITOR_BINARY = '/usr/bin/vi'
    LINE_ENDING = UNIX_LINE_ENDING
    CONFIGHEADER = CONFIGHEADER_UNIX
    CONFIGHEADER_SIZE = len(CONFIGHEADER)


def check_get_file(file):
    """
    Check if file is encrypted using the sasecli file encryption method.
    :param file: path to file.
    :return: True if a valid encrypted file, False if fails encrypted check. Also salt and encrypted data returned.
    """
    with open(file, 'rb') as file_handle:
        first_line = file_handle.readline()
        file_data = file_handle.read()

    if first_line[0:ENCRYPTEDHEADER_LEN] == ENCRYPTEDHEADER[0:ENCRYPTEDHEADER_LEN]:
        # get salt (end of first line until newline)
        salt = first_line[ENCRYPTEDHEADER_LEN:-1]
        return True, salt, file_data
    else:
        return False, b'', b''


def generate_salt(length=63):
    """
    Generate a random salt
    :param length: Length of salt
    :return: b64 string for salt
    """
    return base64.urlsafe_b64encode(os.urandom(length))


def derive_key(password_provided, salt=None):
    """
    Derive a key from password and salt. If salt is not supplied, generate.
    :param password_provided: Password
    :param salt: Salt. If not provided, generate.
    :return: b64 string for password
    """
    if salt is None:
        salt = generate_salt()

    password = password_provided.encode()  # Convert to type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=64,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def write_encrypted_file(file, data, password_provided, salt=None):
    """
    Write encrypted sasecli configuration file, with header
    :param file: File path and name
    :param data: Data to write
    :param password_provided: Password to encrypt the file
    :param salt: Salt to encrypt (optional, will generate.)
    :return: No return.
    """
    if salt is None:
        salt = generate_salt()

    key = derive_key(password_provided, salt)

    fernet = Fernet(key)

    if type(data) is not bytes:
        bytes_data = data.encode()
    else:
        bytes_data = data

    encrypted = fernet.encrypt(bytes_data)

    with open(file, 'wb') as file_handle:
        file_handle.write(ENCRYPTEDHEADER + salt + b'\n')
        file_handle.write(encrypted)
    return


def read_encrypted_file(file, password_provided, salt=None, force=None):
    """
    Read encrypted sasecli configuration file
    :param file: File path and name
    :param password_provided: Password to decrypt the file
    :param salt: Manual salt. default = Read salt from file.
    :param force: Ignore content checks on decrypted file content.
    :return: Tuple of success(boolean) and binary data.
    """
    is_encrypted, file_salt, encrypted_payload = check_get_file(file)
    if not is_encrypted:
        return False, b""

    if salt is None:
        salt = file_salt

    # get key
    key = derive_key(password_provided, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_payload)
    except (InvalidSignature, InvalidToken) as e:
        # Could not decrypt data. Return False.
        return False, b""

    # Check if file decrypted successfully by looking for expected YAML header.
    if len(decrypted_data) < CONFIGHEADER_SIZE or decrypted_data[0:CONFIGHEADER_SIZE].lower() != CONFIGHEADER:
        if force:
            # return the mangled data
            return True, decrypted_data
        else:
            # If doesn't match, header is mangled or password is wrong
            return False, b""

    return True, decrypted_data


def edit_config_file():
    """
    Helper to edit a sasecli configuration file with an editor. Decrypts to tempfile if encrypted.
    :return: No return
    """

    global DEFAULT_EDITOR_BINARY

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0} ({1})".format('sasecli_edit_config', __version__))

    editor_group = parser.add_argument_group('sasecli_edit_config', 'SASECLI Edit Configuration Arguments')
    editor_group.add_argument("--editor", "-E", help=f"Use this program to edit configuration. Editor must support"
                                                     f"filename as first argument. Default: {DEFAULT_EDITOR_BINARY}",
                              default=None)

    args = vars(parser.parse_args())

    # check config file.
    home_dir = pathlib.Path.home()
    config_file_path = str(home_dir) + DIRSLASH + CONFIG_DIR + DIRSLASH + CONFIG_YAML
    config_directory_path = str(home_dir) + DIRSLASH + CONFIG_DIR
    config_dir_exists = os.path.exists(config_directory_path)
    config_file_exists = os.path.isfile(config_file_path)

    if not config_dir_exists or not config_file_exists:
        if not config_dir_exists:
            sys.stderr.write(f"Error: Config directory {config_directory_path} and file {config_file_path} do not "
                             f"exist. Please run `sasecli` to create them before using this utility.\n")
            sys.stderr.flush()
            sys.exit(1)
        else:
            sys.stderr.write(f"Error: Config file {config_file_path} does not "
                             f"exist. Please run `sasecli` to create it before using this utility.\n")
            sys.stderr.flush()
            sys.exit(1)

    # check if custom editor is given, and if it exists.
    if args['editor'] is not None:
        command_exists = shutil.which(args['editor'])
        if command_exists is not None:
            sys.stdout.write(f"Using Editor '{args['editor']}'.\n")
            sys.stdout.flush()
            DEFAULT_EDITOR_BINARY = args['editor']
        else:
            sys.stderr.write(f"Error: Custom Editor {args['editor']} not found or unable to run. Exiting.\n")
            sys.stderr.flush()
            sys.exit(1)

    # file exists, get ready to edit.
    file_pw = None
    is_encrypted, _, _ = check_get_file(config_file_path)
    if is_encrypted:
        # prompt for password.
        file_pw = getpass('Configuration Encrypted. Password: ')
        read_success, file_data = read_encrypted_file(config_file_path, file_pw)
        if not read_success:
            sys.stderr.write(f"\nUnable to load config '{config_file_path}'. Please verify password.\n")
            sys.stderr.flush()
            sys.exit(1)

    else:
        # cleartext
        with open(config_file_path, "rb") as config_fd:
            file_data = config_fd.read()

    # create temp file to edit.
    root, ext = os.path.splitext(os.path.realpath(config_file_path))
    fd, tmp_path = tempfile.mkstemp(suffix=ext)
    if SYSTEM_TYPE == "WINDOWS":
        # Windows TMP also needs to close the file descriptor to proceed. (file will be deleted subsequently)
        os.close(fd)

    # if windows, need to close tempfile before moving on.

    editor_command = DEFAULT_EDITOR.format(DEFAULT_EDITOR_BINARY, tmp_path)

    newconfig_data = None
    # try to edit.
    try:
        # put the unencrypted config in the temporary file
        with open(tmp_path, 'wb') as temp_fd:
            temp_fd.write(file_data)

        # drop the user into an editor on the tmp file
        os.system(editor_command)

        # load changes
        with open(tmp_path, 'rb') as newconfig_fd:
            newconfig_data = newconfig_fd.read()

    except Exception as e:
        pass

    finally:
        # No matter what, remove the temp file.
        if SYSTEM_TYPE != "WINDOWS":
            # windows systems already closed the FD by here.
            os.close(fd)
        os.remove(tmp_path)

    # check for new config data.
    if newconfig_data is None:
        sys.stderr.write(f"Error: Read of edited configuration from temporary file failed. Changes were not written to"
                         f"{config_file_path}, and are likely lost.\n Exiting.\n")
        sys.stderr.flush()
        sys.exit(1)

    # check that header wasn't mangled.
    if len(newconfig_data) < CONFIGHEADER_SIZE or newconfig_data[0:CONFIGHEADER_SIZE].lower() != CONFIGHEADER:
        # get the actual data for printing
        result_output = newconfig_data.decode('utf-8') if len(newconfig_data) < CONFIGHEADER_SIZE \
            else newconfig_data[0:CONFIGHEADER_SIZE].decode('utf-8')
        sys.stderr.write(f"Error: Header in edited file was corrupted.\n"
                         f"Expected:\n"
                         f"\"{CONFIGHEADER.decode('utf-8')}\"\n"
                         f"Got:\n"
                         f"\"{result_output}\"\n"
                         f"Changes were discarded and not written to {config_file_path}.\n"
                         f"Exiting.\n")
        sys.stderr.flush()
        sys.exit(1)

    # check for changes
    if newconfig_data == file_data:
        # no changes.
        sys.stdout.write(f"No changes to configuration file detected. Exiting without saving.\n")
        sys.exit(0)

    # write file depending on encryption.
    if is_encrypted:
        # encrypted file.
        sys.stdout.write(f"Saving updated encrypted configuration: ")
        # write file, create new salt.
        write_encrypted_file(config_file_path, newconfig_data, file_pw)
        sys.stdout.write(f"Done.\n")
    else:
        # unencrypted file.
        sys.stdout.write(f"Saving updated configuration: ")
        with open(config_file_path, 'wb') as config_fd:
            config_fd.write(newconfig_data)
        sys.stdout.write(f"Done.\n")


def decrypt_config_file():
    """
    Helper to decrypt a sasecli configuration file.
    :return: No return
    """
    # Parse arguments
    parser = argparse.ArgumentParser(description="{0} ({1})".format('sasecli_decrypt_config', __version__))

    editor_group = parser.add_argument_group('sasecli_decrypt_config', 'SASECLI Decrypt Configuration Arguments')
    editor_group.add_argument("--force", "-F", help=f"Export configurations to alternate file. Don't verify contents "
                                                    f"after decryption. Must specify filename to decrypt contents into,"
                                                    f" since config may be corrupt. Valid password is still required.",
                              default=None)

    args = vars(parser.parse_args())

    # check config file.
    home_dir = pathlib.Path.home()
    config_file_path = str(home_dir) + DIRSLASH + CONFIG_DIR + DIRSLASH + CONFIG_YAML
    config_directory_path = str(home_dir) + DIRSLASH + CONFIG_DIR
    config_dir_exists = os.path.exists(config_directory_path)
    config_file_exists = os.path.isfile(config_file_path)

    if not config_dir_exists or not config_file_exists:
        if not config_dir_exists:
            sys.stderr.write(f"Error: Config directory {config_directory_path} and file {config_file_path} do not "
                             f"exist. Please run 'sasecli' to create them before using this utility.\n")
            sys.stderr.flush()
            sys.exit(1)
        else:
            sys.stderr.write(f"Error: Config file {config_file_path} does not "
                             f"exist. Please run `sasecli` to create it before using this utility.\n")
            sys.stderr.flush()
            sys.exit(1)

    file_pw = None
    is_encrypted, _, _ = check_get_file(config_file_path)
    if is_encrypted:
        # prompt for password.
        file_pw = getpass('Configuration Encrypted. Password: ')
        read_success, file_data = read_encrypted_file(config_file_path, file_pw, force=args['force'])
        if not read_success:
            sys.stderr.write(f"\nUnable to load config '{config_file_path}'. Please verify password.\n")
            sys.stderr.flush()
            sys.exit(1)
    else:
        sys.stderr.write(f"Configuration file is not encrypted or corrupted and unable to decrypt. "
                         f"Exiting.\n")
        sys.exit(1)

    if args['force'] is not None:
        # we are force-saving possibly corrupt or invalid data.
        sys.stdout.write(f"Force-saving configuration decrypted to {args['force']}: ")
        with open(args['force'], 'wb') as config_fd:
            config_fd.write(file_data)
        sys.stdout.write(f"Done.\n")
    else:
        # save decrypted file.
        sys.stdout.write(f"Saving configuration decrypted: ")
        with open(config_file_path, 'wb') as config_fd:
            config_fd.write(file_data)
        sys.stdout.write(f"Done.\n")


def encrypt_config_file():
    """
    Helper to encrypt a sasecli configuration file.
    :return: No return
    """

    # check config file.
    home_dir = pathlib.Path.home()
    config_file_path = str(home_dir) + DIRSLASH + CONFIG_DIR + DIRSLASH + CONFIG_YAML
    config_directory_path = str(home_dir) + DIRSLASH + CONFIG_DIR
    config_dir_exists = os.path.exists(config_directory_path)
    config_file_exists = os.path.isfile(config_file_path)

    if not config_dir_exists or not config_file_exists:
        if not config_dir_exists:
            sys.stderr.write(f"Error: Config directory {config_directory_path} and file {config_file_path} do not "
                             f"exist. Please run `sasecli` to create them before using this utility.\n")
            sys.stderr.flush()
            sys.exit(1)
        else:
            sys.stderr.write(f"Error: Config file {config_file_path} does not "
                             f"exist. Please run `sasecli` to create it before using this utility.\n")
            sys.stderr.flush()
            sys.exit(1)

    is_encrypted, _, _ = check_get_file(config_file_path)
    if is_encrypted:
        sys.stderr.write(f"Configuration file is already Encrypted. No Encryption Required. Exiting.\n")
        sys.exit(1)

    # cleartext
    with open(config_file_path, "rb") as config_fd:
        file_data = config_fd.read()

    # check that header isn't mangled.
    if len(file_data) < CONFIGHEADER_SIZE or file_data[0:CONFIGHEADER_SIZE].lower() != CONFIGHEADER:
        result_output = file_data.decode('utf-8') if len(file_data) < CONFIGHEADER_SIZE else \
            file_data[0:CONFIGHEADER_SIZE].decode('utf-8')
        sys.stderr.write(f"Error: Header in config file {config_file_path} is corrupted.\n"
                         f"Expected:\n"
                         f"\"{CONFIGHEADER.decode('utf-8')}\"\n"
                         f"Got:\n"
                         f"\"{result_output}\"\n"
                         f"Not encrypting, please fix header and retry.\n"
                         f"Exiting.\n")
        sys.stderr.flush()
        sys.exit(1)

    # prompt for password.
    file_password = None
    while file_password is None:
        first_pw = getpass('Enter password to encrypt file: ')
        if first_pw == "":
            sys.stderr.write("Error: Password cannot be blank.\n")
            sys.stderr.flush()
            # continue and re-enter
            continue
        second_pw = getpass('Confirm file encryption password: ')
        if first_pw != second_pw:
            sys.stdout.write("Error: Passwords do not match.\n")
            sys.stdout.flush()
        else:
            # got a match!
            file_password = first_pw
            break

    # save encrypted file.
    sys.stdout.write(f"Saving encrypted configuration: ")
    # encrypted file.
    # write file, create new salt.
    write_encrypted_file(config_file_path, file_data, file_password)
    sys.stdout.write(f"Done.\n")


def create_config_file():
    """
    Helper to generate a sasecli configuration file.
    :return: Booklean, True if config created encrypted - otherwise False.
    """

    # check config file.
    home_dir = pathlib.Path.home()
    config_file_path = str(home_dir) + DIRSLASH + CONFIG_DIR + DIRSLASH + CONFIG_YAML
    config_directory_path = str(home_dir) + DIRSLASH + CONFIG_DIR
    config_dir_exists = os.path.exists(config_directory_path)
    config_file_exists = os.path.isfile(config_file_path)

    if not config_dir_exists or not config_file_exists:
        file_password = None
        while file_password is None:
            first_pw = getpass('Enter password to encrypt file, or blank for cleartext []: ')
            if first_pw == "":
                # want cleartext. Continue
                break
            second_pw = getpass('Confirm file encryption password: ')
            if first_pw != second_pw:
                sys.stdout.write("Error: Passwords do not match.\n")
                sys.stdout.flush()
            else:
                # got a match!
                file_password = first_pw
                break
        # write file
        # make directories if they don't exist
        os.makedirs(config_directory_path, mode=0o700, exist_ok=True)

        if file_password is not None:
            # write encrypted file.
            write_encrypted_file(config_file_path, DEFAULT_YAML_WITH_COMMENTS, file_password)
            os.chmod(config_file_path, 0o600)
            sys.stdout.write(f"\nCreated '{config_file_path} (encrypted)'.\n")
            sys.stdout.flush()
            return True
        else:
            # write file using default
            with open(config_file_path, "wb") as f:
                os.chmod(config_file_path, 0o600)
                f.write(DEFAULT_YAML_WITH_COMMENTS)
            sys.stdout.write(f"\nCreated '{config_file_path} (cleartext)'.\n")
            sys.stdout.flush()
            return False
    else:
        sys.stderr.write(f"Error: Config file {config_file_path} already exists. Exiting.\n")
        sys.stderr.flush()
        sys.exit(1)
