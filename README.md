# jwks-server

# PROJECT 1
1. Key Generation
- Implement RSA key pair generation.
- Associate a Key ID (kid) and expiry timestamp with each key.
2. Web server with two handlers
- Serve HTTP on port 8080
- A RESTful JWKS endpoint that serves the public keys in JWKS format.
- Only serve keys that have not expired.
- A /auth endpoint that returns an unexpired, signed JWT on a POST request.
- If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry.

The code is written in Python. Flask and PyJWT are used as well as python's cryptography (pyca/cryptography).

References:

https://pyjwt.readthedocs.io/en/latest/usage.html

https://auth0.com/blog/how-to-handle-jwt-in-python/

https://jwt.io/

# PROJECT 2
This will continue extending the JWKS server created in PROJECT 1.

The goal of this project is to:
1. Create/Open a SQLite DB file at start
2. Write the private keys to that file
3. Modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database

POST:/auth will:
1. read a private key from the database
   - if expired: read an expired key
   - if not: read a valid unexpired key
2. Sign a JWT with the private key and return the JWT

GET:/.well-known/jwks.json will:
1. Read all valid, non-expired private keys from the database.
2. Create a JWKS response from those private keys.

References:

https://docs.python.org/3/library/sqlite3.html
