from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid
import base64
import sqlite3

app = Flask(__name__)

# creates db file if not exists
db_file = "totally_not_my_privateKeys.db"
con = sqlite3.connect(db_file)
cur = con.cursor()

# creates table |kid (auto generated) | private key | expiration timestamp
table_schema ="""
CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
"""
cur.execute(table_schema)
con.commit()

# private key gen
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# get public key
public_key = private_key.public_key()

# serialize private key using pem
priv_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM, 
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# serialize pub key
pub_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM, 
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# current time
timeNow = int(datetime.now(timezone.utc).timestamp())

# save private key
insert_privKey = """
INSERT INTO keys (key, exp) 
VALUES (?, ?)
"""

cur.execute(insert_privKey, (priv_key_pem, timeNow))
con.commit()

cur.close()
con.close()

# Generate a new key ID
kid = str(uuid.uuid4())
exp_time = datetime.now(timezone.utc) + timedelta(minutes=10)

# JWKS dictionary containing the initial key
jwks_dict = {
    "keys": [
        {
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).rstrip(b'=').decode(
                'utf-8'),
            "e": "AQAB",
            "exp": int(exp_time.timestamp()),
        }
    ]
}

# Store the JWKS in a list
jwks = [jwks_dict["keys"]]

# Endpoint to generate JWT
@app.route('/auth', methods=['POST'])
def generate_jwt():
    try:
        # connect to database
        con = sqlite3.connect(db_file)
        cur = con.cursor()

        # set to false before beginning
        expired = request.args.get('expired', False)

        if expired:
            # expired 20 seconds ago
            exp_time = datetime.now(timezone.utc) - timedelta(seconds=20)
        else:
            # will expire in 10 minutes
            exp_time = datetime.now(timezone.utc) + timedelta(minutes=10)

        # new kid for each jwt
        kid = str(uuid.uuid4())

        # insert into db
        insert_db = """
        INSERT INTO keys (key, exp) 
        VALUES (?, ?) 
        """
        cur.execute(insert_db, (priv_key_pem, exp_time.timestamp()))
        con.commit()

        cur.close()
        con.close()
        
        # create a new key and append to jwks_dict
        if not expired: 
            new_key = {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).rstrip(b'=').decode('utf-8'),
                "e": "AQAB",
                "exp": int(exp_time.timestamp()),
                }
            jwks_dict["keys"].append(new_key)

       # header
        header = {"kid": kid, "alg": "RS256", "typ": "JWT"}
        # token creation
        token = jwt.encode({'exp': exp_time.timestamp()}, private_key, algorithm='RS256', headers=header)
        
        print("\n Encoded token: ", token, "\n")
        return token, 200
    
    except jwt.ExpiredSignatureError:
        print("Expired token: ", token, "\n")
        return "Token expired", 401

    except jwt.InvalidTokenError as error_generating_token:
        print("POST: Error generating token: " , {error_generating_token}, "\n")
        return "POST: Error generating token: ", 401


# Endpoint to retrieve JWKs
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    try:
        return jsonify(jwks_dict), 200
    
    except Exception as e:
        print("Error getting JWKs:", e)
        return "Error getting JWKs", 500

if __name__ == '__main__':
    app.run(port=8080)
