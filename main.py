from flask import Flask
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa 
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
  

#generate key pair and jwk
def gen_key():
    #private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
  )
    
  #public key
  public_key = private_key.public_key()

  #
  
  #expiration set for 1 year
  exp_time = datetime.datetime.utcnow() + datetime.timedelta(days=365)
  
  #encode jwk
  
  
  #/auth POST
  
  
  #/.well-known/jwks.json GET



if __name__ == '__main__':
    #run on port 8080
    app.run(port=8080)
