import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth, firestore
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# --- Configuration ---
# API Key from your index.html (Required for logging in via REST API)
FIREBASE_WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY")

# Initialize Firebase Admin SDK
# Make sure you place serviceAccountKey.json in the same directory
cred_path = os.path.join(os.path.dirname(__file__), 'serviceAccountKey.json')

if os.path.exists(cred_path):
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
else:
    print("WARNING: serviceAccountKey.json not found. Firebase calls will fail.")


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')

    if not email or not password or not name:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # 1. Create user in Firebase Authentication
        user_record = auth.create_user(
            email=email,
            password=password,
            display_name=name
        )

        # 2. Create user document in Firestore
        user_data = {
            'uid': user_record.uid,
            'email': email,
            'displayName': name,
            'role': 'student',  # Default role
            'createdAt': firestore.SERVER_TIMESTAMP
        }
        db.collection('users').document(user_record.uid).set(user_data)

        return jsonify({
            'message': 'User created successfully',
            'uid': user_record.uid,
            'email': email
        }), 201

    except auth.EmailAlreadyExistsError:
        return jsonify({'error': 'Email already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    # Since Firebase Admin SDK doesn't support "Sign In with Password" (it's for admin tasks),
    # we use the Firebase Auth REST API to verify credentials.
    request_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    try:
        response = requests.post(request_url, json=payload)
        res_data = response.json()

        if response.status_code == 200:
            # Login successful
            id_token = res_data.get('idToken')
            local_id = res_data.get('localId')
            
            # Optionally fetch extra user data from Firestore to return to frontend
            user_doc = db.collection('users').document(local_id).get()
            user_info = user_doc.to_dict() if user_doc.exists else {}

            return jsonify({
                'token': id_token,
                'user': user_info
            }), 200
        else:
            return jsonify({'error': res_data.get('error', {}).get('message', 'Login failed')}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)