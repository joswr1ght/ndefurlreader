#! /usr/bin/env python
# Joshua Wright, josh@wr1ght.net, 2017
import re, argparse
from smartcard.System import readers
import datetime, sys
import pdb
import ndef
import requests
from requests.exceptions import ConnectionError
import threading
import tempfile
import os
import subprocess
import time


# ACS ACR122U NFC Reader
# This command below is based on the "API Driver Manual of ACR122U NFC Contactless Smart Card Reader"
COMMAND = [0xFF, 0xCA, 0x00, 0x00, 0x00] # handshake cmd needed to initiate data transfer

# get all the available readers
r = readers()
print "Available readers:", r
if len(r) == 0:
	print "Cannot open NFC reader. Make sure it is attached to the VM (1)."
	sys.exit(1)

def stringParser(dataCurr):
#--------------String Parser--------------#
	#([85, 203, 230, 191], 144, 0) -> [85, 203, 230, 191]
	if isinstance(dataCurr, tuple):
		temp = dataCurr[0]
		code = dataCurr[1]
	#[85, 203, 230, 191] -> [85, 203, 230, 191]
	else:
		temp = dataCurr
		code = 0

	dataCurr = ''

	#[85, 203, 230, 191] -> bfe6cb55 (int to hex reversed)
	for val in temp:
		# dataCurr += (hex(int(val))).lstrip('0x') # += bf
		dataCurr += format(val, '#04x')[2:] # += bf

	#bfe6cb55 -> BFE6CB55
	dataCurr = dataCurr.upper()

	#if return is successful
	if (code == 144):
		return dataCurr

def readTag(page):
	readingLoop = 1
	while(readingLoop):
		try:
			connection = reader.createConnection()
			status_connection = connection.connect()
			connection.transmit(COMMAND)
			#Read command [FF, B0, 00, page, #bytes]
			resp = connection.transmit([0xFF, 0xB0, 0x00, int(page), 0x04])
			dataCurr = stringParser(resp)

			#only allows new tags to be worked so no duplicates
			if(dataCurr is not None):
				return dataCurr
				break
			else:
				print "Something went wrong reading page " + str(page)
				break
		except Exception,e: 
			if(waiting_for_beacon ==1):
				time.sleep(1)
				continue
			else:
				readingLoop=0
				# print str(e)
				break

# Download and run the executable
def downloadRun(url):
	print "Begin thread."
	child = None
	
	print "Downloading " + url + " in thread."
	try:
		r = requests.get(url, allow_redirects=True)
	except ConnectionError:
		print "Cannot connect to the system at " + url + " to download file."
		return # ends thread

	fd,fname = tempfile.mkstemp(suffix=".exe")
	os.write(fd, r.content)
	os.close(fd)

	try:
		child = subprocess.Popen([fname])
	except WindowsError:
		print "Cannot execute binary from " + url
		return
	return_code = child.wait()
	if (child != None and return_code != 0):
		print "Executable from " + url + " returned non-zero exit status: " + str(return_code)
	
	print "End thread."
	

URICODES = {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
    0x05: "tel:",
    0x06: "mailto:",
    0x07: "ftp://anonymous:anonymous@",
    0x08: "ftp://ftp.",
    0x09: "ftps://",
    0x0A: "sftp://",
    0x0B: "smb://",
    0x0C: "nfs://",
    0x0D: "ftp://",
    0x0E: "dav://",
    0x0F: "news:",
    0x10: "telnet://",
    0x11: "imap:",
    0x12: "rtsp://",
    0x13: "urn:",
    0x14: "pop:",
    0x15: "sip:",
    0x16: "sips:",
    0x17: "tftp:",
    0x18: "btspp://",
    0x19: "btl2cap://",
    0x1A: "btgoep://",
    0x1B: "tcpobex://",
    0x1C: "irdaobex://",
    0x1D: "file://",
    0x1E: "urn:epc:id:",
    0x1F: "urn:epc:tag:",
    0x20: "urn:epc:pat:",
    0x21: "urn:epc:raw:",
    0x22: "urn:epc:",
    0x23: "urn:nfc:"
}

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Read NFC tags')
	usingreader_group = parser.add_argument_group('usingreader')
	usingreader_group.add_argument('--usingreader', nargs=1, metavar='READER_ID', help='Reader to use [0-X], default is 0')
	wait_group = parser.add_argument_group('wait')
	wait_group.add_argument('--wait', nargs=1, metavar='0|1', help='Wait for beacon before returns [0|1], default is 1')
	allBlocks = ""

	args = parser.parse_args()

	#Choosing which reader to use
	try:
		if args.usingreader:
			usingreader = args.usingreader[0]
			if (int(usingreader) >= 0 and int(usingreader) <= len(r)-1):
				reader = r[int(usingreader)]
			else:
				reader = r[0]
		else:
			reader = r[0]
	except IndexError:
		print "Cannot open NFC reader. Make sure it is attached to the VM (2)."
		sys.exit(1)

	#Disabling wait for answer if wait == 0
	if args.wait:
		wait = args.wait[0]
		if (int(wait) == 0 ):
			waiting_for_beacon = 0
		else:
			waiting_for_beacon = 1
	else:
		waiting_for_beacon = 1

	print "Using:", reader
	while (1):
		for page in xrange(4,20):
			allBlocks += readTag(page)

		print "\n" + allBlocks
		
		data = allBlocks.decode('hex')
		
		# Remove first two bytes, conf data not NDEF
		data = data[2:]
		
		# First three bytes are NDEF record, 2nd byte offset if the payload length after TNF type byte (4 byte header)
		recordlen = ord(data[2])
		ndefdata = data[0:recordlen+4]

		record = ndef.NdefMessage(ndefdata).records[0]
		#pdb.set_trace()
		print '  tnf:    ', record.tnf
		print '  type:   ', record.type
		print '  id:     ', record.id
		print '  payload:', record.payload	
		
		if (record.type == "U"):
			url = URICODES[ord(record.payload[0])] + record.payload[1:]
			print "URL is " + url
			
			if url[0:7].lower() == "http://" and url[-4:].lower() == ".exe":
				print "Downloading and executing file."
				processThread = threading.Thread(target=downloadRun, args=(url,))
				processThread.start()
		
		# Delay before reading next tag
		time.sleep(5)
	
