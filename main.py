from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid
import base64

app = Flask(__name__)

# rsa key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
# get public key
public_key = private_key.public_key()


#*****************************************************
# public key generation to verify signature on jwt.io
pub_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo
                                      )
# load private key
loaded_pub_key_pem = serialization.load_pem_public_key(pub_key_pem, backend=default_backend)

# use this in jwt.io to verify signature
print("Public Key:", pub_key_pem.decode('utf-8'))
#****************************************************


kid = str(uuid.uuid4())
exp_time = datetime.now(timezone.utc) + timedelta(minutes=10)

#  
jwks_dict = {
    "keys": [
        {
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).rstrip(b'=').decode('utf-8'),
            "e": "AQAB",
            "exp": int(exp_time.timestamp()),
        }
    ]
}

# Store the JWK in a list
jwks = [jwks_dict["keys"]]
print(jwks)

# Endpoint to generate JWT
@app.route('/auth', methods=['POST'])
def generate_jwt():
    try:
        # set to false before beginning
        expired = request.args.get('expired', False)

        if expired:
            # expired 20 minutes ago
            exp_time = datetime.now(timezone.utc) - timedelta(minutes=20)
        else:
            # will expire in 10 minutes
            exp_time = datetime.now(timezone.utc) + timedelta(minutes=10)

        header = {"kid": kid, "alg": "RS256", "typ": "JWT"}

        # token creation
        token = jwt.encode({'exp': exp_time.timestamp()}, private_key, algorithm='RS256', headers=header)
        print("Encoded token: ", token)
        return token, 200
    
    except jwt.ExpiredSignatureError:
        print("Expired token: ", token)

    except Exception as error_generating_token:
        print("Error generating token: , {error_generating_token}")
        return "Error generating token: ", 500


# Endpoint to retrieve JWKs
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    try:
        return jsonify(jwks_dict), 200
    
    except Exception as get_jwks_error:
        print("Error getting JWKs: {get_jwks_error}")
        return "Error getting JWKs", 500


if __name__ == '__main__':
    app.run(port=8080)
