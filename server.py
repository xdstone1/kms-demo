from flask import Flask,request
from aliyunsdkcore import client
from aliyunsdkkms.request.v20160120 import GenerateDataKeyRequest
from aliyunsdkkms.request.v20160120 import DecryptRequest
import json,base64
from Crypto.Cipher import AES

app = Flask(__name__)

accesskeyid = "YOUR-KEY-ACCESS-ID"
accesssecret = "YOUR-KEY-ACCESS-SECRET"
keyid = "YOUR-KEY-ID"
regionid = "us-west-1"

def createdatakey():
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

    return cipherdatakey

def decryptdata(ciphertext, cipherdatakey):
    clt = client.AcsClient(accesskeyid, accesssecret, regionid)
    decrequest = DecryptRequest.DecryptRequest()
    decrequest.set_CiphertextBlob(cipherdatakey)
    decrequest.set_accept_format("json")
    decrequest.set_protocol_type("https")

    decresp = clt.do_action_with_exception(decrequest)
    plaintext = json.loads(decresp)
    datakey = base64.b64decode(plaintext["Plaintext"])  # get plaintext datakey back

    cipherfile = base64.b64decode(ciphertext)
    iv = cipherfile[:AES.block_size]
    aes = AES.new(datakey,AES.MODE_CBC, iv)
    return aes.decrypt(cipherfile[AES.block_size:]).decode('utf-8') #use datakey to decrypt the content of file: cipherfile.txt and print it out 

@app.route('/')
def index():
    return 'Hello Flask!\n'

@app.route('/applyDataKey')
def applyDataKey():
    return createdatakey() + "\n"

@app.route("/sendEncryptedData",methods = ['GET',"POST"])
def sendEncryptedData():
    if request.method == "POST":
        ciphertext = request.form["ciphertext"]
        cipherdatakey = request.form["cipherdatakey"]
        print("After decryption:" + decryptdata(ciphertext, cipherdatakey))
        return "decryptdata success"
    return "decryptdata fail, Methods is error"

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)    
