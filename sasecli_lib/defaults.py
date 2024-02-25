#!/usr/bin/env python
#
# Default templates / Data
#

from . import __version__

DEFAULT_YAML_WITH_COMMENTS = f"""---
type: sasecli
version: {__version__}

# This section allows you to specify a default CLIENT_ID, CLIENT_SECRET, DEVICE_USER and DEVICE_PASSWORD. These will be 
# used by default if others are not specified.
# 
# If the DEVICE_USER or DEVICE_PASSWORD fails, you will be prompted again to finish logging in when connecting to the 
# device.

DEFAULT:
    CLIENT_ID:
    CLIENT_SECRET:
    DEVICE_USER: 
    DEVICE_PASSWORD: 

# If your CLIENT_ID has access to multiple tenants, you can put tenant-specific DEVICE_USER and DEVICE_PASSWORD here.
#
# The name match must match the TSG name exactly or use TSG ID. In the case of duplicate TSG names, you will have to
# specify by TSG_ID. 

MSP:
  "Exact Example TSG NAME1":
    DEVICE_USER:
    DEVICE_PASSWORD: 
    
  "1111111111111111":
    DEVICE_USER:
    DEVICE_PASSWORD: 
""".encode("utf-8")

DEFAULT_CONTROL_CHAR_DICT = {
    '\0': '^@',  # Null character
    '\1': '^A',  # Start of heading
    '\2': '^B',  # Start of text
    '\3': '^C',  # End of text
    '\4': '^D',  # End of transmission
    '\5': '^E',  # Enquiry
    '\6': '^F',  # Acknowledge
    '\a': '^G',  # Audible bell
    '\b': '^H',  # Backspace
    '\t': '^I',  # Horizontal tab
    '\n': '^J',  # Line feed
    '\v': '^K',  # Vertical tab
    '\f': '^L',  # Form feed
    '\r': '^M',  # Carriage return
    '\x0e': '^N',  # Shift out
    '\x0f': '^O',  # Shift in
    '\x10': '^P',  # Data link escape
    '\x11': '^Q',  # Device control 1
    '\x12': '^R',  # Device control 2
    '\x13': '^S',  # Device control 3
    '\x14': '^T',  # Device control 4
    '\x15': '^U',  # Negative Acknowledge
    '\x16': '^V',  # Synchronous idle
    '\x17': '^W',  # End of transmission block
    '\x18': '^X',  # Cancel
    '\x19': '^Y',  # End of medium
    '\x1a': '^Z',  # Substitute
    '\x1b': '^[',  # Escape
    '\x1c': '^\\',  # File separator
    '\x1d': '^]',  # Group separator
    '\x1e': '^^',  # Record separator
    '\x1f': '^-',  # Unit separator
}
