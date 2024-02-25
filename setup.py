from setuptools import setup
from sasecli_lib import __version__, __author__, __email__
import sys

with open('README.md') as f:
    long_description = f.read()

if sys.version_info[:3] < (3, 6, 1):
    raise Exception("websockets requires Python >= 3.6.1.")


setup(name='sasecli',
      version=__version__,
      description='`Command-line access to available Prisma SASE CLI resources. (Specifically, Prisma SD-WAN as of now.)`',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/ebob9/sasecli',
      author=__author__,
      author_email=__email__,
      license='MIT',
      install_requires=[
            'prisma_sase >= 6.3.1b1',
            'websockets >= 12.0',
            'thefuzz >= 0.22.1',
            'tabulate >= 0.9.0',
            'cryptography >= 42.0.2',
            'pyyaml >= 5.3.1'
      ],
      packages=['sasecli_lib'],
      classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: End Users/Desktop",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12"
      ],
      python_requires='>=3.10.1',
      entry_points={
            'console_scripts': [
                  'sasecli = sasecli_lib:toolkit_client',
                  'prisma_sdwan_generic_ws = sasecli_lib:generic_client',
                  'sasecli_edit_config = sasecli_lib.file_crypto:edit_config_file',
                  'sasecli_decrypt_config = sasecli_lib.file_crypto:decrypt_config_file',
                  'sasecli_encrypt_config = sasecli_lib.file_crypto:encrypt_config_file',
                  'sasecli_create_defaultconfig = sasecli_lib.file_crypto:create_config_file'
            ]
      },
      )
