from pymongo import MongoClient
import bcrypt

# Connect directly to localhost MongoDB
client = MongoClient('mongodb://localhost:27017/NIDS')
db = client.NIDS

# Create user in the users collection (which your app checks)
user_data = {
    'username': 'admin',
    'password': bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()),
    'email': 'admin@example.com'
}

# First, check if user already exists
existing_user = db.users.find_one({'username': 'admin'})
if existing_user:
    print("User already exists, updating password")
    db.users.update_one(
        {'username': 'admin'},
        {'$set': {'password': user_data['password']}}
    )
else:
    # Insert new user
    result = db.users.insert_one(user_data)
    print(f"New user created with ID: {result.inserted_id}")

print("Done - use username 'admin' and password 'admin123' to login")
client.close()