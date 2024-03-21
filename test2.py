import unittest
from flask import Flask
import sqlite3
from main2 import app

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

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_table(self):
        # open connection to database
        con = sqlite3.connect("totally_not_my_privateKeys.db")
        cur = con.cursor()

        # select all from table
        cur.execute("SELECT * FROM keys")
        rows = cur.fetchall()

        # close connection
        cur.close()
        con.close()

        # check if rows are there
        self.assertTrue(len(rows) > 0, "No rows found.." )

        print("Database table: ")
        for row in rows:
            print(row)


if __name__ == '__main__':
    unittest.main()
