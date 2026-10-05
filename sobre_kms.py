import boto3, json, base64
from cryptography.fernet import Fernet

kms = boto3.client("kms", region_name="us-east-1")        
key_id = kms.create_key()["KeyMetadata"]["KeyId"]         

def cifrar(msg):
    k = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")   
    c = Fernet(base64.urlsafe_b64encode(k["Plaintext"])).encrypt(msg.encode())  
    sobre = {"msg": c.decode(), "key": base64.b64encode(k["CiphertextBlob"]).decode()}
    del k                                                 
    json.dump(sobre, open("sobre.json", "w"))             
    return sobre

def descifrar():
    s = json.load(open("sobre.json"))
    k = kms.decrypt(CiphertextBlob=base64.b64decode(s["key"]))["Plaintext"]  
    msg = Fernet(base64.urlsafe_b64encode(k)).decrypt(s["msg"].encode()).decode()
    return msg, base64.b64encode(k).decode()              

print(cifrar("Hola KMS"))
print(descifrar())