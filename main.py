from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa 
import jwt
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)

# private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
# public key
public_key = private_key.public_key()

#kid
kid = str(uuid.uuid1())

# expiration
exp_time = datetime.utcnow() + timedelta(days=365)

#jwks dictionary encoding
jwks = {
    "keys": [
        {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": public_key.public_numbers().n,
        "e": public_key.public_numbers().e,
        "exp": int(exp_time.timestamp()),
        }
    ]
}

# generate JWT
@app.route('/auth', methods=['POST'])
def gen_jwt():
    # expiration
    exp_time = datetime.utcnow() + timedelta(minutes=2)
    expired = request.args.get('expired', '').lower() == 'true'

    payload = {'kid': kid, 'exp': int(exp_time.timestamp())}
    header = {"alg": "RS256", "typ": "JWT", "kid": kid} 
    
    try:
        token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)
        return jsonify({'JWT token': token})
        
    except jwt.ExpiredSignatureError:
        return jsonify({'ERROR': 'Expired JWT'}), 401


# JWKS Endpoint - this serves public keys
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    if jwks_list:
        response =  jsonify(jwks_list[0])
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
    else:
        return jsonify({'ERROR': 'JWKS not found'}), 404



if __name__ == '__main__':
    app.run(port=8080)
