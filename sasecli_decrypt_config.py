#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

from sasecli_lib.file_crypto import decrypt_config_file

if __name__ == '__main__':
    sys.exit(decrypt_config_file())
