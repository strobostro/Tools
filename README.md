Multihash is a simple quick & dirty python script to calculate various hashes (md5, sha1, sha256 and ssdeep) for a file and request VirusTotal (API key required) and provide synthetic results (detection rate and 3 most common names)

Multihash requires the following python modules: sys, hashlib, pydeep, json, urllib, urllib2, collections (Counter) and argparse

Usage: python multihash.py <input_file_path>

Enter your VT API key at the following line:
parameters = {"resource": sha256hash.hexdigest(),"apikey": "<your_vt_api_key_here>"}
