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

@app.route('/admin/upload-questions', methods=['POST'])
def upload_questions():
    # 1. Verify Authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        # Verify the Firebase ID token
        auth.verify_id_token(token)
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401

    # 2. Process Data
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Empty payload'}), 400

    try:
        if 'db' not in globals():
            return jsonify({'error': 'Database not initialized'}), 500

        batch = db.batch()
        collection_ref = db.collection('questions')
        
        items = data if isinstance(data, list) else [data]
        
        for item in items:
            doc_ref = collection_ref.document()
            batch.set(doc_ref, item)
        
        batch.commit()
        return jsonify({'message': f'Successfully uploaded {len(items)} questions'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- User Management Routes for Admin ---

@app.route('/admin/users', methods=['GET'])
def get_users():
    # 1. Verify Admin
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_doc = db.collection('users').document(uid).get()
        if not (user_doc.exists and user_doc.to_dict().get('role') == 'admin'):
             return jsonify({'error': 'Admin privileges required'}), 403
    except Exception as e:
        return jsonify({'error': 'Invalid token', 'details': str(e)}), 401

    # 2. Fetch users from Firestore
    try:
        users_ref = db.collection('users').order_by('createdAt', direction=firestore.Query.DESCENDING).limit(10)
        users_docs = users_ref.stream()
        
        users_list = []
        for doc in users_docs:
            user_data = doc.to_dict()
            if 'createdAt' in user_data and hasattr(user_data['createdAt'], 'isoformat'):
                user_data['createdAt'] = user_data['createdAt'].strftime('%d.%m.%Y')
            users_list.append(user_data)
            
        return jsonify(users_list), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    # 1. Verify Admin
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_doc = db.collection('users').document(uid).get()
        if not (user_doc.exists and user_doc.to_dict().get('role') == 'admin'):
             return jsonify({'error': 'Admin privileges required'}), 403
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401

    # 2. Delete user
    try:
        auth.delete_user(user_id)
        db.collection('users').document(user_id).delete()
        return jsonify({'message': f'User {user_id} deleted successfully'}), 200
    except auth.UserNotFoundError:
        db.collection('users').document(user_id).delete()
        return jsonify({'message': f'User {user_id} deleted from Firestore (was not in Auth).'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    # 1. Verify Admin
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    token = auth_header.split(' ')[1]
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_doc = db.collection('users').document(uid).get()
        if not (user_doc.exists and user_doc.to_dict().get('role') == 'admin'):
             return jsonify({'error': 'Admin privileges required'}), 403
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401

    # 2. Get data and update
    data = request.get_json()
    if not data or 'displayName' not in data:
        return jsonify({'error': 'Missing displayName in request body'}), 400
    try:
        new_name = data['displayName']
        auth.update_user(user_id, display_name=new_name)
        db.collection('users').document(user_id).update({'displayName': new_name})
        updated_doc = db.collection('users').document(user_id).get()
        user_data = updated_doc.to_dict()
        if 'createdAt' in user_data and hasattr(user_data['createdAt'], 'isoformat'):
            user_data['createdAt'] = user_data['createdAt'].strftime('%d.%m.%Y')
        return jsonify(user_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats', methods=['GET'])
def get_admin_stats():
    # 1. Verify Admin
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_doc = db.collection('users').document(uid).get()
        if not (user_doc.exists and user_doc.to_dict().get('role') == 'admin'):
             return jsonify({'error': 'Admin privileges required'}), 403
    except Exception as e:
        return jsonify({'error': 'Invalid token', 'details': str(e)}), 401

    # 2. Fetch stats from Firestore
    try:
        # Note: For very large collections, streaming all docs for a count can be slow/costly.
        # Consider using a distributed counter for production at scale.
        questions_docs = db.collection('questions').stream()
        question_count = len(list(questions_docs))

        users_docs = db.collection('users').stream()
        user_count = len(list(users_docs))

        return jsonify({
            'questionCount': question_count,
            'userCount': user_count
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)