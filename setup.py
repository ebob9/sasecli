from setuptools import setup
import sys

with open('README.md') as f:
    long_description = f.read()

if sys.version_info[:3] < (3, 6, 1):
    raise Exception("websockets requires Python >= 3.6.1.")


setup(name='sasecli',
      version='0.0.1b1',
      description='`Command-line access to available Prisma SASE CLI resources. (Specifically, Prisma SD-WAN as of now.)`',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/ebob9/sasecli',
      author='Aaron Edwards',
      author_email='sasecli@ebob9.com',
      license='MIT',
      install_requires=[
            'cloudgenix >= 6.1.1b1',
            'fuzzywuzzy >= 0.17.0',
            'pyyaml >= 3.13'
      ],
      packages=['sasecli_lib'],
      classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: End Users/Desktop",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3.10"
      ],
      python_requires='>=3.10.1',
      entry_points={
            'console_scripts': [
                  'sasecli = sasecli_lib:toolkit_client',
            ]
      },
      )
