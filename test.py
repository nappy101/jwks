import unittest
from flask import Flask
from main import app

class TestApp(unittest.TestCase):
    def setUp(self):
        # flask
        self.app = app.test_client()
        print("\n")

    # expired
    def test_expJWT(self):
        print("Expired ...")
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        print("\n")

    # auth
    def test_auth(self):
        print("POST test ...")
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        print("\n")


    # get
    def test_get(self):
        print("GET test ...")
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        print("\n")



if __name__ == '__main__':
    unittest.main()
