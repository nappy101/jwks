# jwks-server
PROJECT 1
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
