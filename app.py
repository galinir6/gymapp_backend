from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from bson import ObjectId
import logging
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mykey'
app.config['JWT_SECRET_KEY'] = 'Mykey'

# Enable CORS
CORS(app)

# Initialize JWT manager
jwt = JWTManager(app)

# Initialize MongoDB client
client = MongoClient('mongodb://localhost:27017/')
db = client.gymapp
users_collection = db.users
workouts_collection = db.workouts

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

# Utility functions
def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, hashed_password):
    return check_password_hash(hashed_password, password)

# Routes
# Register - add new user to database with hashed password
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        logging.error('Register failed: Missing name, email, or password')
        return jsonify({"msg": "Name, email, and password are required"}), 400

    if users_collection.find_one({'email': email}):
        logging.warning(f'Register failed: User with email {email} already exists')
        return jsonify({"msg": "User already exists"}), 409

    hashed_password = hash_password(password)
    users_collection.insert_one({'name': name, 'email': email, 'hashed_password': hashed_password})
    logging.info(f'User {email} registered successfully')

    return jsonify({"msg": "User registered successfully"}), 201


# Login - check for user with email and password, send token
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({'email': email})
    if not user or not verify_password(password, user['hashed_password']):
        logging.warning(f'Login failed for {email}: Invalid email or password')
        return jsonify({"msg": "Invalid email or password"}), 401

    access_token = create_access_token(identity=str(user['_id']))
    logging.info(f'User {email} logged in successfully')
    return jsonify({
        "user": {"email": user['email']},
        "access_token": access_token
    }), 200


# Add a workout to the database , connected to logged user
@app.route('/api/workouts/add', methods=['POST'])
@jwt_required()
def add_workout():
    data = request.get_json()
    user_id = get_jwt_identity()

    name = data.get('name')
    details = data.get('details')
    location = data.get('location')
    coordinates = data.get('coordinates')

    if not name or not details or not location or not coordinates:
        logging.error('Add workout failed: Missing name, details, location, or coordinates')
        return jsonify({"msg": "Name, details, location, and coordinates are required"}), 400

    workout = {
        'user_id': user_id,
        'name': name,
        'details': details,
        'location': location,
        'coordinates': coordinates,
        'date': datetime.utcnow().isoformat()
    }

    workouts_collection.insert_one(workout)
    logging.info(f'Workout added for user {user_id}')
    return jsonify({"msg": "Workout added successfully"}), 201


# Get workouts of logged user using the id from token
@app.route('/api/workouts/history', methods=['GET'])
@jwt_required()
def get_workout_history():
    user_id = get_jwt_identity()
    workouts = list(workouts_collection.find({'user_id': user_id}))

    for workout in workouts:
        workout['_id'] = str(workout['_id'])

    logging.info(f'Workout history retrieved for user {user_id}')
    return jsonify(workouts), 200

# Get information of logged user using token
@app.route('/api/auth/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        logging.error(f'Get user failed: User {user_id} not found')
        return jsonify({"msg": "User not found"}), 404

    logging.info(f'User details retrieved for user {user_id}')
    return jsonify({"name": user['name'], "email": user['email'], "id": str(user_id)}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
