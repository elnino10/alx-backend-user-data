#!/usr/bin/env python3
""" app module """

from flask import Flask, jsonify, request
from auth import Auth
from typing import Dict

app = Flask(__name__)
AUTH = Auth()


@app.route("/", strict_slashes=False)
def home() -> str:
    """home route"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> Dict:
    """users registration endpoint"""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": f'"{email}"', "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
