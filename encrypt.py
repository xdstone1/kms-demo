#coding:utf-8
from aliyunsdkcore import client
from aliyunsdkkms.request.v20160120 import GenerateDataKeyRequest

import ConfigParser
import json

from Crypto.Cipher import AES 
from Crypto import Random
import base64

def aes256pad(s):
	return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

if __name__ == '__main__':
	Config = ConfigParser.ConfigParser();
	Config.read("./userinfo.txt")
	accesskeyid = Config.get("UserInfo","UserKey");
	accesssecret = Config.get("UserInfo","UserSec");
	regionid = Config.get("UserInfo","RegionId");
	keyid = Config.get("UserInfo","KmsKeyId");
	
	clt = client.AcsClient(accesskeyid, accesssecret, regionid)
	genrequest = GenerateDataKeyRequest.GenerateDataKeyRequest()

	genrequest.set_KeyId(keyid);
	genrequest.set_KeySpec("AES_256") # or AES_128
	genrequest.set_accept_format("json")
	genrequest.set_protocol_type("https")
	genresp = clt.do_action_with_exception(genrequest)

	datakeydict = json.loads(genresp)
	datakey = base64.b64decode(datakeydict["Plaintext"]) #here we got the datakey with plaintext 
	cipherdatakey = datakeydict["CiphertextBlob"] # here we got encrypted datakey

	with open('cipherkey','w') as key:
		key.write(cipherdatakey) # store encrypted datakey into file: cipherkey
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(datakey, AES.MODE_CBC, iv) #use daatakey to initiate an object 
	with open('password.txt','r') as fp:
		filedata = aes256pad(fp.read()) #read content of 'password.txt'
		print "plain text content:"
		print filedata
		cipherfile = base64.b64encode(iv + cipher.encrypt(filedata)) #encrypt the content
		with open('cipherfile.txt','w') as output:
			output.write(cipherfile) #write the encrypted content to file: cipherfile.txt
		with open('cipherfile.txt','r') as cipherfile:
			print "plain text after encryption:"
			print cipherfile.read() 
