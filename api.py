import os
import re
import logging
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_file, abort
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.utils import secure_filename
from passlib.hash import pbkdf2_sha256
from pymongo.errors import DuplicateKeyError

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://127.0.0.1:27017/ByteBucket"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["JWT_SECRET_KEY"] = "YourSecretKey"  # Replace with your actual secret key
mongo = PyMongo(app)
jwt = JWTManager(app)

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Ensure upload folder exists
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# Collections
users = mongo.db.users
users.create_index("username", unique=True)
users.create_index("email", unique=True)


# Response helpers
def success_response(data, status_code=200):
    return jsonify({"success": True, "data": data}), status_code


def error_response(message, status_code=400):
    return jsonify({"success": False, "error": message}), status_code


# User registration endpoint
@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    phone = data.get("phone")
    role = data.get("role")

    # Validate data
    if not re.match(
        r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password
    ):
        return error_response(
            "Password must contain letters, numbers, and special characters."
        )
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return error_response("Invalid email format.")

    hashed_password = pbkdf2_sha256.hash(password)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Insert user
    try:
        users.insert_one(
            {
                "username": username,
                "password": hashed_password,
                "email": email,
                "phone": phone,
                "role": role,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
        )
        return success_response("User registered successfully.")
    except DuplicateKeyError:
        return error_response("Username or email already exists.")


# User login endpoint
@app.route("/api/login", methods=["POST"])
def login_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = users.find_one({"username": username})
    if user and pbkdf2_sha256.verify(password, user["password"]):
        access_token = create_access_token(identity=username)
        return success_response({"access_token": access_token})
    return error_response("Invalid username or password.", 401)


# Protected route: get user profile
@app.route("/api/profile", methods=["GET"])
@jwt_required()
def get_profile():
    username = get_jwt_identity()
    user = users.find_one({"username": username}, {"_id": 0, "password": 0})
    if user:
        return success_response(user)
    return error_response("User not found.", 404)


# Update user profile
@app.route("/api/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    username = get_jwt_identity()
    data = request.json
    email = data.get("email")
    phone = data.get("phone")
    role = data.get("role")

    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return error_response("Invalid email format.")

    try:
        users.update_one(
            {"username": username},
            {
                "$set": {
                    "email": email,
                    "phone": phone,
                    "role": role,
                    "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                }
            },
        )
        return success_response("Profile updated successfully.")
    except DuplicateKeyError:
        return error_response("Email already exists.")
    except Exception as e:
        logger.error("Profile update error: %s", e)
        return error_response("An error occurred while updating profile.")


# Upload files
@app.route("/api/upload", methods=["POST"])
@jwt_required()
def upload_file():
    username = get_jwt_identity()
    files = request.files.getlist("file")
    category = request.form.get("category", "Other")

    if not files:
        return error_response("No files provided.")

    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
    category_folder = os.path.join(user_folder, category)
    os.makedirs(category_folder, exist_ok=True)

    for file in files:
        filename = secure_filename(file.filename)
        file_path = os.path.join(category_folder, filename)
        file.save(file_path)
        logger.info("File uploaded by %s: %s", username, filename)

    return success_response("Files uploaded successfully.")


# List files
@app.route("/api/files", methods=["GET"])
@jwt_required()
def list_files():
    username = get_jwt_identity()
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
    files_structure = {
        category: os.listdir(os.path.join(user_folder, category))
        for category in os.listdir(user_folder)
        if os.path.isdir(os.path.join(user_folder, category))
    }
    return success_response(files_structure)


# Download file
@app.route("/api/files/download/<category>/<filename>", methods=["GET"])
@jwt_required()
def download_file(category, filename):
    username = get_jwt_identity()
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], username, category, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return error_response("File not found.", 404)


# Delete file
@app.route("/api/files/delete/<category>/<filename>", methods=["DELETE"])
@jwt_required()
def delete_file(category, filename):
    username = get_jwt_identity()
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], username, category, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        logger.info("File deleted by %s: %s", username, filename)
        return success_response("File deleted successfully.")
    return error_response("File not found.", 404)


if __name__ == "__main__":
    app.run(debug=True)
