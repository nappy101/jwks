from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa 
import jwt
import uuid
from datetime import datetime, timedelta, timezone
import base64

app = Flask(__name__)

# jwks_url = "http://127.0.0.1:8080/.well-known/jwks.json"

jwks_list = []

def key_gen():
    # private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # public key
    public_key = private_key.public_key()

    return private_key, public_key

# key gen()
private_key, public_key = key_gen()

# PEM public key generation
pub_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo
                                      )
# load private key
loaded_pub_key_pem = serialization.load_pem_public_key(pub_key_pem, backend=default_backend)

# use this in jwt.io to verify signature
print("Public Key (PEM):", pub_key_pem.decode('utf-8'))

# kid
kid = str(uuid.uuid1())

# expiration
exp_time = datetime.now(timezone.utc) + timedelta(seconds=60)

#jwks dictionary encoding
jwks = {
    "keys": [
        {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).rstrip(b'=').decode('utf-8'),
        "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(4, 'big')).rstrip(b'=').decode('utf-8'),
        "exp": int(exp_time.timestamp()),
        }
    ]
}

jwks_list.append(jwks)

# generate JWT
@app.route('/auth', methods=['POST'])
def gen_jwt():
    print("Generating................................")    

    # issue time (iat)
    issued_time = datetime.now(timezone.utc)
    
    header = {
                "alg": "RS256", 
                "typ": "JWT", 
                "kid": kid
            }      
       
    payload = {
                'exp': int(exp_time.timestamp()),
                'iat': int(issued_time.timestamp())
            }
          
    # creates jwt and signs it with private key
    token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)
    
    # use this in jwt.io to verify the signature
    print("Encoded Token: ", token)

    try:
        decoded_token = jwt.decode(token, loaded_pub_key_pem, algorithms=['RS256'])
        print("Decoded Token: ", decoded_token)
        
        return jsonify({'JWT token': token})
        
    # check for expiration    
    except jwt.ExpiredSignatureError:
        print("JWT Token Expired")

        # 401 unauthorized signature
        return jsonify({'ERROR': 'Expired JWT'}), 401

# JWKS Endpoint - this serves public keys
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    if jwks_list:
        # first item in list
        response =  jsonify(jwks_list[0])
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
    else:
        # 404 not found
        return jsonify({'ERROR': 'JWKS not found'}), 404

if __name__ == '__main__':
    app.run(port=8080)
