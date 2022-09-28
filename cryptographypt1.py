from encodings import utf_8
from flask import Flask, request
import scrypt, binascii, hmac, hashlib
import json


app =Flask(__name__)

@app.route('/crypto1/sha256', methods=["POST"])
def sha256_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    data = values["msg"].encode()
    hashData = hashlib.sha256(data).hexdigest()
    response = {
        "hash": "0x"+hashData
    }

    return json.dumps(response), 201

@app.route('/crypto1/sha512', methods=["POST"])
def sha512_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    data = values["msg"].encode()
    hashData = hashlib.sha512(data).hexdigest()
    response = {
        "hash": "0x"+hashData
    }

    return json.dumps(response), 201

@app.route('/crypto1/ripemd160', methods=["POST"])
def ripemd160_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    data = values["msg"].encode()
    hashData = hashlib.new('ripemd160', data).hexdigest()
    response = {
        "hash": "0x"+hashData
    }

    return json.dumps(response), 201

@app.route('/crypto1/hmac', methods=["POST"])
def hmac_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg", "key"]
    if not all(k in values for k in required):
        return "Missing values", 400

    msg = values['msg'].encode()
    key = values['key'].encode()
    byteData = hmac.new(key, msg, hashlib.sha256).digest()
    final = binascii.hexlify(byteData)
    response = {
        "hmac": "0x"+final.decode()
    }

    return response, 201

@app.route('/crypto1/scrypt', methods=["POST"])
def scrypt_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["password", "salt"]
    if not all(k in values for k in required):
        return "Missing values", 400

    passwd = values['password']
    sal = values["salt"]
    salt = sal.encode()

    key = scrypt.hash(passwd, salt, 16384, 16, 1)
    unlock = binascii.hexlify(key)

    response = {
        "key": "0x"+unlock.decode()
    }

    return response, 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

