# coding: utf8
import sys
import hashlib
import pydeep
import json
import urllib
import urllib2
from collections import Counter
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("filepath", help="input file path", type=str)
args = parser.parse_args()

tohash = args.filepath
md5hash = hashlib.md5()
sha1hash = hashlib.sha1()
sha256hash = hashlib.sha256()

try:
	with open(tohash, 'rb') as afile:
		buf = afile.read()
		md5hash.update(buf)
		sha1hash.update(buf)
		sha256hash.update(buf)
	afile.close()

	ssdeephash = pydeep.hash_file(tohash)

	print "md5 hash:", md5hash.hexdigest()
	print "sha1 hash:",sha1hash.hexdigest()
	print "sha256 hash:",sha256hash.hexdigest()
	print "ssdeep hash:",ssdeephash

	try:
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		parameters = {"resource": sha256hash.hexdigest(),"apikey": "<your_vt_api_key_here>"}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json = json.loads(response.read())
	
		count = 0
		detect = 0
		names = list()
		
		for av in json['scans'].keys():
			count = count +1 
			if ( json['scans'][av]['detected'] == True ):
				detect = detect + 1
				names.append(json['scans'][av]['result'])
	
		counted = Counter(names)
	
		print "VirusTotal detection rate: "+str(detect)+"/"+str(count)
		print counted.most_common(3)

	except IOError:
		print "network problem"

except IOError:
	print "file not found"
