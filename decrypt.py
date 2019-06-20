#coding:utf-8
from aliyunsdkcore import client
from aliyunsdkkms.request.v20160120 import DecryptRequest

import ConfigParser
import json

from Crypto.Cipher import AES 
import base64

def aes256unpad(s):
	return s[:-ord(s[len(s)-1:])] 

if __name__ == '__main__':
	Config = ConfigParser.ConfigParser();
	Config.read("./userinfo.txt")
	accesskeyid = Config.get("UserInfo","UserKey");
	accesssecret = Config.get("UserInfo","UserSec");
	regionid = Config.get("UserInfo","RegionId");
	
	clt = client.AcsClient(accesskeyid, accesssecret, regionid)
	with open('cipherkey','r') as fp:
		cipherdatakey = fp.read() # get the content of file: cipherkey
		decrequest = DecryptRequest.DecryptRequest()
		decrequest.set_CiphertextBlob(cipherdatakey)
		decrequest.set_accept_format("json")
		decrequest.set_protocol_type("https")
		decresp = clt.do_action_with_exception(decrequest)
		plaintext = json.loads(decresp)
		datakey = base64.b64decode(plaintext["Plaintext"])# get plaintext datakey back
		with open('cipherfile.txt','r') as cipher:
			ciphercontent = cipher.read()
			cipherfile = base64.b64decode(ciphercontent)
			print "cipher file content:"
			print ciphercontent
			print ''
			iv = cipherfile[:AES.block_size]
			aes = AES.new(datakey, AES.MODE_CBC, iv)
			print 'after decryption:'
			print aes.decrypt(cipherfile[AES.block_size:]).decode('utf-8') #use datakey to decrypt the content of file: cipherfile.txt and print it out

