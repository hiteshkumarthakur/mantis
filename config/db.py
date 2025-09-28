from pymongo import MongoClient

# MongoDB connection URI
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "mantis"

# Create a MongoClient instance
client = MongoClient(MONGO_URI)

# Access the mantis database
db = client[DATABASE_NAME]

Assets_collection = db["assets_collection"]
Findings_collection = db["findings_collection"]
users_collection = db["users_collection"]
