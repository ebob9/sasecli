# sasecli
Command-line access to available Prisma SASE CLI resources. (Specifically, Prisma SD-WAN as of now.)

#### Synopsis
This is a placeholder for the soon-to-be released utility. 

#### Requirements
* Active Prisma SASE Account
* Python >=3.10
* Prisma SD-WAN IONs running 5.2.1+ Software
* Python modules:
    * prisma_sase   - <https://github.com/PaloAltoNetworks/prisma-sase-sdk-python>
    * websockets   - <https://websockets.readthedocs.io/en/stable/>
    * fuzzywuzzy   - <https://github.com/seatgeek/fuzzywuzzy/>
    * pyyaml       - <https://pyyaml.org/wiki/PyYAMLDocumentation>
    * tabulate     - <https://github.com/astanin/python-tabulate>
    * cryptography - <https://github.com/pyca/cryptography>

#### Installation
* Via PIP as simple as `pip install --upgrade sasecli`
* Clone this repository from GitHub, then `cd sasecli; pip install --upgrade .`

#### License
MIT

#### Version
| Version | Build | Changes                                                  |
| ------- | ----- |----------------------------------------------------------|
| **2.0.1** | **b1** | First release of `sasecli`, ported from `cgxsh` v1.0.2b1 |
| **0.0.1** | **b1** | Placeholder for future release.                          |

## For more info
 * Please look at Prisma SASE information on <https://docs.paloaltonetworks.com/sase>