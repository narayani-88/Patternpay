"""MongoDB helper for PatternPay.
Loads MONGODB_URI from .env and exposes ready-to-use collection handles.
"""
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

MONGODB_URI = os.getenv('MONGODB_URI')
if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI not found in environment variables (.env file)")

# Initialise client and database (db name comes from URI path or defaults to patternpay)
client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
try:
    client.admin.command('ping')
except Exception as exc:
    raise RuntimeError(f"Cannot connect to MongoDB Atlas: {exc}")

# If a specific DB name is provided at the end of the URI we use it, otherwise 'patternpay'
try:
    _db_name = client.get_default_database().name  # will work if URI ends with /dbname
except Exception:
    _db_name = 'patternpay'

db = client[_db_name]

users_col = db['users']
accounts_col = db['accounts']
transactions_col = db['transactions']

def ensure_indexes():
    """Create common indexes for uniqueness and performance."""
    users_col.create_index('username', unique=True)
    accounts_col.create_index('account_number', unique=True)
    transactions_col.create_index([('account_number', 1), ('created_at', -1)])

# Run on import
ensure_indexes()

def now():
    return datetime.utcnow()
