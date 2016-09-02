Multihash is a simple quick & dirty python script to:
    - calculate various hashes (md5, sha1, sha256 and ssdeep) for a file
    - request VirusTotal (API key required) and provide synthetic results (detection rate and 3 most common names)

Multihash requires the following python modules:
    - sys
    - hashlib
    - pydeep
    - json
    - urllib
    - urllib2
    - collections (Counter)
    - re
    - argparse

Usage: python multihash.py <input_file_path>
