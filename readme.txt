pre-request:
1. install python
2. use "pip install aliyuni-python-sdk-kms"
3. create a RAM accout with AK and save the AccessKey information
4. in alibabcloud console, go to KMS service and select one region and create one key and save that keyid
5. put above four information into file: UserInfo.txt


How to use the sample code:
1. #python encryt.py  //will encryt the content of 'password.txt' and generate 2 files: cipherkey and cipherfile.txt, in cipherkey file is encrypted datakey, in cipherfile.txt is encrypted content of 'password.txt' 
2. #python decrypt.py //will return the plaintext contnet of 'password.txt' 



