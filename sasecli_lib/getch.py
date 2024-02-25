#!/usr/bin/env python
import sys
import locale

windows_arrow_to_posix = {
    b'\xe0H': '\x1b[A',
    b'\xe0P': '\x1b[B',
    b'\xe0K': '\x1b[D',
    b'\xe0M': '\x1b[C',
}


class _Getch:
    """
    Gets a single character from standard input. Does not echo to the screen.
    Derived from http://code.activestate.com/recipes/134892/
    """
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()

    def __call__(self, raw=False):
        return self.impl(raw=raw)


class _GetchUnix:
    final_encoding = 'utf-8'
    detected_encoding = 'utf-8'
    termios = object

    def __init__(self):
        import termios
        self.termios = termios
        self.detected_encoding = locale.getpreferredencoding()

    def __call__(self, raw=False):
        """
        Call and parse read chars before sending.
        :param raw: No effect on POSIX/UNIX (always string)
        :return: char (or multiple char) pressed.
        """
        # get one or more char here.
        first_char = self._do_getch()
        # future logic for encoding issues here.
        # future logic for remapping to appropriate keypress here.
        return first_char

    def custom_tty_mode(self, fd, when=2):  # termio.TCSAFLUSH = 2, but can't use at declaration due to dynamic import.
        """
        Set a custom tty mode. We want to keep OUTPUT normalization/post-processing, but stop input processing.
        RAW breaks output too much, CBREAK allows CTRL-C and Suspend to not be caught by getch.
        Great info for this came from "https://utcc.utoronto.ca/~cks/space/blog/unix/CBreakAndRaw".
        Also inspired from tty.py.
        :param fd: File Descriptor
        :param when: When to (Default to TCSAFLUSH)
        :return: No return, mutates File Descriptor directly
        """
        mode = self.termios.tcgetattr(fd)
        # IFLAG
        # We do not want to set ICRNL
        # "With this disabled, carriage returns (^M, '\r') are not turned into newlines (^J, '\n') on input
        # (normally you can't tell them apart and both will terminate the current line)"
        mode[0] = mode[0] & ~(self.termios.BRKINT | self.termios.INPCK | self.termios.ISTRIP |
                              self.termios.IXON)
        # OFLAG
        # We do not want to set OPOST
        # "Disables any 'implementation-defined' output processing. On Linux (and probably many others)
        # This is the setting that normally turns a newline into a CR-NL sequence."
        # mode[1] = mode[1] & ~(self.termios.OPOST)
        # CFLAG
        mode[2] = mode[2] & ~(self.termios.CSIZE | self.termios.PARENB)
        mode[2] = mode[2] | self.termios.CS8
        # LFLAG
        mode[3] = mode[3] & ~(self.termios.ECHO | self.termios.ICANON | self.termios.IEXTEN | self.termios.ISIG)
        # CC
        mode[6][self.termios.VMIN] = 1
        mode[6][self.termios.VTIME] = 0
        self.termios.tcsetattr(fd, when, mode)

    def _do_getch(self):
        """
        Do actual POSIX char obtaining
        :return: char
        """
        fd = sys.stdin.fileno()
        old_settings = self.termios.tcgetattr(fd)
        try:
            # Don't set raw - any stdout becomes raw as well. cbreak mode is more output friendly.
            # self.tty.setraw(sys.stdin.fileno())
            # Dont set cbreak either. That lets control-c and others break out.
            # self.tty.setcbreak(sys.stdin.fileno())
            # Custom TTY mode it is!
            self.custom_tty_mode(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            self.termios.tcsetattr(fd, self.termios.TCSADRAIN, old_settings)
        return ch


class _GetchWindows:
    final_encoding = 'utf-8'
    detected_encoding = 'utf-8'
    msvcrt = object

    def __init__(self):
        import msvcrt
        self.msvcrt = msvcrt
        self.detected_encoding = locale.getpreferredencoding()

    def __call__(self, raw=False):
        """
        Call and parse read chars before sending.
        :param raw: send bytes string instead of decoding to detected encoding.
        :return: char (or multiple char) pressed.
        """
        # get one or more char here.
        first_char = self._do_getch()
        if first_char == b'\xe0':
            # arrow encoding issues - remap here to UNIX arrow sequences.
            second_char = self._do_getch()
            both_chars = first_char + second_char
            posix_arrow = windows_arrow_to_posix.get(both_chars)

            if posix_arrow:
                # got a valid arrow sequence
                return posix_arrow
            else:
                # ok. Somehow we got here. send both chars raw or decoded based on kwarg.
                if raw:
                    return both_chars
                else:
                    return both_chars.decode(self.detected_encoding)

        else:
            # not an arrow or other special case. Return.
            if raw:
                return first_char
            else:
                return first_char.decode(self.detected_encoding)

    def _do_getch(self):
        return self.msvcrt.getch()


getch = _Getch()
