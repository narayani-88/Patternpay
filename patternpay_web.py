"""PatternPay Flask app backed by MongoDB Atlas.
This replaces the previous SQLAlchemy/SQLite implementation.
"""
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.datastructures import ImmutableMultiDict
from datetime import datetime
from bson.objectid import ObjectId
import random
import os
import json

# Local helper that exposes users_col, accounts_col, transactions_col
from db import users_col, accounts_col, transactions_col, client, _db_name  # type: ignore

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'patternpay-secret')

# Initialize SocketIO with CORS and additional configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25
)

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def generate_account_number() -> str:
    while True:
        acc_num = ''.join(str(random.randint(0, 9)) for _ in range(10))
        if not accounts_col.find_one({'account_number': acc_num}):
            return acc_num

# ---------------------------------------------------------------------------
# Sample data loader (runs once at startup if empty)
# ---------------------------------------------------------------------------

def ensure_sample_data():
    if users_col.estimated_document_count() == 0:
        # Create a default user
        password_hash = generate_password_hash('password')
        user_id = users_col.insert_one({
            'username': 'user',
            'password_hash': password_hash,
            'full_name': 'John Doe',
            'email': 'john@example.com',
            'created_at': datetime.utcnow(),
        }).inserted_id

        acc_num = generate_account_number()
        accounts_col.insert_one({
            'account_number': acc_num,
            'account_type': 'Savings',
            'balance': 5000.0,
            'user_id': user_id,
            'created_at': datetime.utcnow(),
        })

        transactions_col.insert_one({
            'account_number': acc_num,
            'transaction_type': 'Deposit',
            'amount': 5000.0,
            'description': 'Initial deposit',
            'created_at': datetime.utcnow(),
        })

ensure_sample_data()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_col.find_one({'username': username})
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']

        if users_col.find_one({'username': username}):
            flash('Username already exists', 'error')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        users_col.insert_one({
            'username': username,
            'password_hash': password_hash,
            'full_name': full_name,
            'email': email,
            'created_at': datetime.utcnow(),
        })
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = users_col.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    user_accounts = list(accounts_col.find({'user_id': ObjectId(session['user_id'])}))
    
    # Get recent transactions for all accounts
    account_numbers = [acc['account_number'] for acc in user_accounts]
    recent_transactions = []
    
    # Get transactions where the user is either sender or receiver
    transactions_cursor = transactions_col.find({
        '$or': [
            {'from_account': {'$in': account_numbers}},
            {'to_account': {'$in': account_numbers}}
        ]
    }).sort('timestamp', -1).limit(5)
    
    # Convert cursor to list and add transaction type and sign
    for tx in transactions_cursor:
        tx['_id'] = str(tx['_id'])  # Convert ObjectId to string for JSON serialization
        if tx['from_account'] in account_numbers:
            tx['transaction_type'] = 'Debit'
            tx['amount'] = -tx['amount']
        else:
            tx['transaction_type'] = 'Credit'
        recent_transactions.append(tx)
    
    # Check which accounts have transactions
    accounts_with_transactions = set()
    for tx in recent_transactions:
        if 'from_account' in tx and tx['from_account'] in account_numbers:
            accounts_with_transactions.add(tx['from_account'])
        if 'to_account' in tx and tx['to_account'] in account_numbers:
            accounts_with_transactions.add(tx['to_account'])
    
    # Store user's socket room in session
    if 'socket_room' not in session:
        session['socket_room'] = f"user_{session['user_id']}"
    
    total_balance = sum(acc['balance'] for acc in user_accounts)
    
    # Get last transaction date for each account
    account_last_dates = {}
    for tx in recent_transactions:
        for acc_field in ['from_account', 'to_account']:
            acc_num = tx.get(acc_field)
            if acc_num in account_numbers and acc_num not in account_last_dates:
                account_last_dates[acc_num] = tx.get('timestamp')
    
    return render_template('dashboard.html', 
                         user=user, 
                         accounts=user_accounts,
                         transactions=recent_transactions,
                         socket_room=session['socket_room'],
                         total_balance=total_balance,
                         account_last_dates=account_last_dates,
                         accounts_with_transactions=accounts_with_transactions)


@app.route('/delete_account/<account_number>', methods=['POST'])
def delete_account(account_number):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    
    # Delete the account and its transactions
    result = accounts_col.delete_one({
        'account_number': account_number,
        'user_id': user_id
    })
    
    if result.deleted_count > 0:
        transactions_col.delete_many({'account_number': account_number})
        flash('Account deleted successfully!', 'success')
    else:
        flash('Account not found or you do not have permission to delete it.', 'error')
    
    return redirect(url_for('dashboard'))


@app.route('/add_account', methods=['GET', 'POST'])
def add_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        account_type = request.form['account_type']
        bank_name = request.form['bank_name']
        initial_balance = float(request.form['initial_balance'])

        account_number = generate_account_number()
        user_id = ObjectId(session['user_id'])

        accounts_col.insert_one({
            'account_number': account_number,
            'account_type': account_type,
            'bank_name': bank_name,
            'balance': initial_balance,
            'user_id': user_id,
            'created_at': datetime.utcnow(),
        })

        transactions_col.insert_one({
            'account_number': account_number,
            'transaction_type': 'Deposit',
            'amount': initial_balance,
            'description': 'Initial deposit',
            'created_at': datetime.utcnow(),
        })

        flash(f'Account created successfully! Account Number: {account_number}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_account.html')


@app.route('/verify_pin', methods=['GET', 'POST'])
def verify_pin():
    print("\n=== PIN Verification Start ===")  # Debug log
    print(f"Method: {request.method}")  # Debug log
    print(f"Headers: {dict(request.headers)}")  # Debug log
    print(f"Session data: {dict(session)}")  # Debug log
    
    # Check if user is logged in
    if 'user_id' not in session:
        print("User not in session")  # Debug log
        if request.is_json or request.content_type == 'application/json':
            return jsonify({'success': False, 'message': 'Please log in'}), 401
        flash('Please log in to continue', 'warning')
        return redirect(url_for('login'))
    
    # Get user from database
    user = users_col.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        print(f"User {session['user_id']} not found in database")  # Debug log
        if request.is_json or request.content_type == 'application/json':
            return jsonify({'success': False, 'message': 'User not found'}), 404
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    # Handle AJAX requests
    if request.is_json or request.content_type == 'application/json':
        print("Processing JSON request")  # Debug log
        if request.method == 'POST':
            try:
                data = request.get_json()
                print(f"Received data: {data}")  # Debug log
                
                pin = data.get('pin')
                next_url = data.get('next') or request.args.get('next') or url_for('dashboard')
                
                print(f"PIN received: {pin}")  # Debug log
                print(f"Next URL: {next_url}")  # Debug log
                
                if not pin or not str(pin).isdigit() or len(str(pin)) < 4 or len(str(pin)) > 6:
                    print("Invalid PIN format")  # Debug log
                    return jsonify({'success': False, 'message': 'Invalid PIN format'}), 400
                
                # Verify PIN (in a real app, this would be hashed and compared)
                user_pin = str(user.get('pin', ''))
                print(f"User PIN: {user_pin}, Provided PIN: {pin}")  # Debug log
                
                if str(pin) != user_pin:
                    print("Incorrect PIN")  # Debug log
                    return jsonify({'success': False, 'message': 'Incorrect PIN'}), 401
                
                # Store PIN verification in session (valid for 5 minutes)
                session['pin_verified'] = True
                session['pin_verified_at'] = datetime.utcnow().timestamp()
                
                print("PIN verification successful")  # Debug log
                print(f"New session data: {dict(session)}")  # Debug log
                
                return jsonify({
                    'success': True,
                    'message': 'PIN verified successfully',
                    'redirect': next_url
                })
                
            except Exception as e:
                print(f"Error in verify_pin: {str(e)}")  # Debug log
                return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
    
    # Handle regular form submission
    if request.method == 'POST':
        pin = request.form.get('pin')
        if not pin or not pin.isdigit() or len(pin) < 4 or len(pin) > 6:
            flash('Invalid PIN format', 'error')
            return redirect(url_for('verify_pin'))
            
        # Verify PIN (in a real app, this would be hashed and compared)
        if pin != user.get('pin'):
            flash('Incorrect PIN', 'error')
            return redirect(url_for('verify_pin'))
        
        # Store PIN verification in session (valid for 5 minutes)
        session['pin_verified'] = True
        session['pin_verified_at'] = datetime.utcnow().timestamp()
        
        # Redirect to the next URL or dashboard
        next_url = request.args.get('next') or url_for('dashboard')
        return redirect(next_url)
    
    # GET request - show PIN verification form
    next_url = request.args.get('next', url_for('dashboard'))
    return render_template('verify_pin.html', next=next_url)


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    print("Transfer route called. Method:", request.method)  # Debug log
    
    if 'user_id' not in session:
        print("User not in session")  # Debug log
        if request.is_json or request.content_type == 'application/json':
            return jsonify({'success': False, 'message': 'Please log in'}), 401
        return redirect(url_for('login'))
    
    # Handle AJAX requests for PIN verification
    if request.method == 'GET' and (request.is_json or request.content_type == 'application/json'):
        print("AJAX GET request received")  # Debug log
        print("Session data:", dict(session))  # Debug log
        
        pin_verified = session.get('pin_verified', False)
        pin_verified_at = session.get('pin_verified_at', 0)
        time_since_verification = datetime.utcnow().timestamp() - pin_verified_at
        
        print(f"PIN verified: {pin_verified}, Verified at: {pin_verified_at}, Time since: {time_since_verification}")  # Debug log
        
        if not pin_verified or time_since_verification > 300:  # 5 minutes
            print("PIN verification required")  # Debug log
            return jsonify({
                'success': False,
                'require_pin': True, 
                'redirect': url_for('verify_pin', next=url_for('transfer'))
            })
            
        print("No PIN verification needed")  # Debug log
        return jsonify({
            'success': True,
            'require_pin': False
        })
    
    if request.method == 'POST':
        # Get form data
        from_account = request.form.get('from_account')
        to_account = request.form.get('to_account')
        try:
            amount = float(request.form.get('amount', 0))
        except (ValueError, TypeError):
            flash('Invalid amount', 'error')
            return redirect(url_for('transfer'))
        
        description = request.form.get('description', 'Bank Transfer')
        
        # Validate input
        if not all([from_account, to_account, amount > 0]):
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('transfer'))
        
        # Get source account
        source = accounts_col.find_one({
            'account_number': from_account,
            'user_id': ObjectId(session['user_id'])
        })
        
        if not source:
            flash('Source account not found', 'error')
            return redirect(url_for('transfer'))
            
        # Check balance
        if source['balance'] < amount:
            flash('Insufficient funds', 'error')
            return redirect(url_for('transfer'))
        
        # Get destination account
        destination = accounts_col.find_one({'account_number': to_account})
        if not destination:
            flash('Destination account not found', 'error')
            return redirect(url_for('transfer'))
        
        # Prevent self-transfer
        if from_account == to_account:
            flash('Cannot transfer to the same account', 'error')
            return redirect(url_for('transfer'))
        
        # Start transaction
        with client.start_session() as session_client:
            with session_client.start_transaction():
                try:
                    # Update source account
                    accounts_col.update_one(
                        {'_id': source['_id']},
                        {'$inc': {'balance': -amount}},
                        session=session_client
                    )
                    
                    # Update destination account
                    accounts_col.update_one(
                        {'_id': destination['_id']},
                        {'$inc': {'balance': amount}},
                        session=session_client
                    )
                    
                    # Record transaction
                    transaction = {
                        'from_account': from_account,
                        'to_account': to_account,
                        'amount': amount,
                        'description': description,
                        'timestamp': datetime.utcnow(),
                        'status': 'completed',
                        'type': 'transfer'
                    }
                    
                    transactions_col.insert_one(transaction, session=session_client)
                    
                    # Commit the transaction
                    session_client.commit_transaction()
                    
                    # Clear PIN verification after successful transfer
                    if 'pin_verified' in session:
                        session.pop('pin_verified')
                    if 'pin_verified_at' in session:
                        session.pop('pin_verified_at')
                    
                    # Send real-time updates
                    socketio.emit('balance_update', {
                        'account_number': from_account,
                        'new_balance': source['balance'] - amount
                    }, room=f"user_{session['user_id']}")
                    
                    # Notify recipient if different user
                    if str(destination['user_id']) != session['user_id']:
                        socketio.emit('balance_update', {
                            'account_number': to_account,
                            'new_balance': destination['balance'] + amount
                        }, room=f"user_{str(destination['user_id'])}")
                        
                        socketio.emit('new_transaction', {
                            'message': f'Received ₹{amount:.2f} from {source["account_number"][-4:]}',
                            'timestamp': datetime.utcnow().isoformat()
                        }, room=f"user_{str(destination['user_id'])}")
                    
                    flash(f'Successfully transferred ₹{amount:.2f} to account ending in {to_account[-4:]}', 'success')
                    return redirect(url_for('dashboard'))
                    
                except Exception as e:
                    session_client.abort_transaction()
                    app.logger.error(f'Transfer failed: {str(e)}')
                    flash('Transfer failed. Please try again.', 'error')
                    return redirect(url_for('transfer'))
    
    # GET request - show transfer form
    user_accounts = list(accounts_col.find({'user_id': ObjectId(session['user_id'])}))
    return render_template('transfer.html', accounts=user_accounts)

@app.route('/upi_payment', methods=['GET', 'POST'])
def upi_payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = users_col.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    # Get user's accounts
    user_accounts = list(accounts_col.find({'user_id': ObjectId(session['user_id'])}))
    if not user_accounts:
        flash('No account found. Please create an account first.', 'danger')
        return redirect(url_for('dashboard'))
        
    account_numbers = [acc['account_number'] for acc in user_accounts]
    
    # Get recent transactions
    recent_transactions = []
    transactions_cursor = transactions_col.find({
        'from_account': {'$in': account_numbers}
    }).sort('timestamp', -1).limit(5)
    
    for tx in transactions_cursor:
        tx['_id'] = str(tx['_id'])
        recent_transactions.append(tx)
    
    if request.method == 'POST':
        upi_id = request.form.get('upi_id')
        amount = float(request.form.get('amount', 0))
        purpose = request.form.get('purpose', 'UPI Payment')
        
        # Get user's primary account (or first account if no primary)
        user_account = next((acc for acc in user_accounts if acc.get('is_primary', False)), user_accounts[0])
        
        # Validate balance
        if user_account['balance'] < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'}), 400
            
        # Deduct amount
        new_balance = user_account['balance'] - amount
        accounts_col.update_one(
            {'_id': user_account['_id']},
            {'$set': {'balance': new_balance}}
        )
        
        # Record transaction
        transaction = {
            'from_account': user_account['account_number'],
            'to_upi': upi_id,
            'amount': amount,
            'type': 'debit',
            'description': purpose,
            'timestamp': datetime.utcnow(),
            'status': 'completed'
        }
        transactions_col.insert_one(transaction)
        
        # Add to recent transactions
        transaction['_id'] = str(transaction['_id'])
        recent_transactions.insert(0, transaction)
        if len(recent_transactions) > 5:
            recent_transactions = recent_transactions[:5]
        
        # Emit balance update
        socketio.emit('balance_update', {
            'account_number': user_account['account_number'],
            'new_balance': new_balance
        }, room=f"user_{session['user_id']}")
        
        flash(f'UPI Payment successful! Amount: ₹{amount} to {upi_id}', 'success')
        return jsonify({
            'success': True,
            'message': f'UPI Payment successful! Amount: ₹{amount} to {upi_id}',
            'new_balance': new_balance
        })

    return render_template('upi_payment.html', 
                         recent_transactions=recent_transactions,
                         user=user)

@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = ObjectId(session['user_id'])
    account_numbers = [acc['account_number'] for acc in accounts_col.find({'user_id': user_id})]
    txns = list(transactions_col.find({'account_number': {'$in': account_numbers}}).sort('created_at', -1))
    return render_template('transactions.html', transactions=txns)


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    user = users_col.find_one({'_id': user_id})
    accounts = list(accounts_col.find({'user_id': user_id}))
    return render_template('profile.html', user=user, accounts=accounts)


@app.route('/ifsc')
def ifsc():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    user = users_col.find_one({'_id': user_id})
    accounts = list(accounts_col.find({'user_id': user_id}))
    return render_template('ifsc.html', user=user, accounts=accounts)


@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = users_col.find_one({'_id': ObjectId(session['user_id'])})
    has_pin = 'pin_hash' in user if user else False
    return render_template('settings.html', has_pin=has_pin)

@app.route('/set_pin', methods=['POST'])
def set_pin():
    if 'user_id' not in session:
        flash('Please log in to set your PIN.', 'error')
        return redirect(url_for('login'))
    pin = request.form.get('pin')
    confirm_pin = request.form.get('confirm_pin')
    if not pin or not confirm_pin or pin != confirm_pin:
        flash('PINs do not match.', 'error')
        return redirect(url_for('settings'))
    if not pin.isdigit() or not (4 <= len(pin) <= 6):
        flash('PIN must be 4-6 digits.', 'error')
        return redirect(url_for('settings'))
    user_id = ObjectId(session['user_id'])
    pin_hash = generate_password_hash(pin)
    users_col.update_one({'_id': user_id}, {'$set': {'pin_hash': pin_hash}})
    flash('PIN set/updated successfully!', 'success')
    return redirect(url_for('settings'))

@app.route('/reset_pin', methods=['POST'])
def reset_pin():
    if 'user_id' not in session:
        flash('Please log in to reset your PIN.', 'error')
        return redirect(url_for('login'))
    password = request.form.get('password')
    new_pin = request.form.get('new_pin')
    confirm_new_pin = request.form.get('confirm_new_pin')
    if not password or not new_pin or not confirm_new_pin:
        flash('All fields are required.', 'error')
        return redirect(url_for('settings'))
    if new_pin != confirm_new_pin:
        flash('New PINs do not match.', 'error')
        return redirect(url_for('settings'))
    if not new_pin.isdigit() or not (4 <= len(new_pin) <= 6):
        flash('PIN must be 4-6 digits.', 'error')
        return redirect(url_for('settings'))
    user_id = ObjectId(session['user_id'])
    user = users_col.find_one({'_id': user_id})
    if not user or not check_password_hash(user['password_hash'], password):
        flash('Incorrect password.', 'error')
        return redirect(url_for('settings'))
    pin_hash = generate_password_hash(new_pin)
    users_col.update_one({'_id': user_id}, {'$set': {'pin_hash': pin_hash}})
    flash('PIN reset successfully!', 'success')
    return redirect(url_for('settings'))

# ----------------- API -----------------

@app.route('/api/accounts')
def api_accounts():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_id = ObjectId(session['user_id'])
    accounts = list(accounts_col.find({'user_id': user_id}))
    return jsonify([
        {
            'account_number': acc['account_number'],
            'account_type': acc['account_type'],
            'balance': acc['balance'],
        } for acc in accounts
    ])

@app.route('/mock_gpay', methods=['GET', 'POST'])
def mock_gpay():
    if 'user_id' not in session:
        if request.is_json:
            return jsonify({'success': False, 'error': 'Please log in first'}), 401
        return redirect(url_for('login'))
    
    # Check if PIN verification is required and valid
    if 'pin_verified' not in session or (datetime.utcnow().timestamp() - session.get('pin_verified_at', 0)) > 300:
        if request.method == 'POST' and request.is_json and request.json.get('verify_pin'):
            # Handle PIN verification from AJAX
            return verify_pin()
        elif request.method == 'POST':
            # Store the payment data in session to process after PIN verification
            session['pending_payment'] = {
                'upi_id': request.form.get('upi_id', '').strip(),
                'amount': request.form.get('amount', '').strip(),
                'purpose': request.form.get('purpose', '').strip(),
                'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            }
            return jsonify({'require_pin': True})
        elif 'pending_payment' in session and request.method == 'GET':
            # If we have a pending payment, show the PIN verification
            return render_template('verify_pin.html',
                                redirect_url=url_for('mock_gpay'),
                                post_url=url_for('verify_pin'))
    
    # Get current user
    current_user = users_col.find_one({'username': session['username']})
    if not current_user:
        if request.is_json:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    # If we have a pending payment and PIN is verified, process it
    if 'pending_payment' in session and request.method != 'POST':
        payment_data = session.pop('pending_payment')
        request.form = ImmutableMultiDict([
            ('upi_id', payment_data['upi_id']),
            ('amount', payment_data['amount']),
            ('purpose', payment_data['purpose'])
        ])
        if payment_data['is_ajax']:
            request._cached_data = json.dumps({
                'upi_id': payment_data['upi_id'],
                'amount': payment_data['amount'],
                'purpose': payment_data['purpose']
            })
            request._parsed_content_type = ['application/json']
    
    # Get all users except current user for the recipients list
    all_users = list(users_col.find({'_id': {'$ne': current_user['_id']}}))
    
    if request.method == 'POST':
        upi_id = request.form.get('upi_id', '').strip()
        amount_str = request.form.get('amount', '').strip()
        purpose = request.form.get('purpose', '').strip()
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # Helper function to return response
        def make_response(success, message, error=None, data=None):
            if is_ajax:
                response = {'success': success, 'message': message}
                if error:
                    response['error'] = error
                if data:
                    response.update(data)
                return jsonify(response)
            else:
                if not success:
                    flash(message, 'error')
                else:
                    flash(message, 'success')
                return redirect(url_for('transactions'))
        
        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                return make_response(False, 'Amount must be greater than 0')
        except (ValueError, TypeError):
            return make_response(False, 'Please enter a valid amount')
        
        # Validate UPI ID
        if '@' not in upi_id:
            return make_response(False, 'Invalid UPI ID. Must contain @ symbol (e.g., name@bank)')
        
        # Start a MongoDB session
        with client.start_session() as mongo_session:
            try:
                # Start a transaction
                mongo_session.start_transaction()
                
                # Find recipient by email (UPI ID) within the transaction
                recipient = users_col.find_one(
                    {'email': upi_id},
                    session=mongo_session
                )
                
                if not recipient:
                    return make_response(False, 'Recipient not found. Please check the UPI ID.')
                
                # Get sender's default account within the transaction
                sender_account = accounts_col.find_one(
                    {'user_id': current_user['_id']},
                    session=mongo_session
                )
                
                if not sender_account:
                    return make_response(False, 'No bank account found for sending money')
                
                # Check if sender has sufficient balance
                if sender_account['balance'] < amount:
                    return make_response(False, 'Insufficient balance for this transaction')
                
                # Get or create recipient's account within the transaction
                recipient_account = accounts_col.find_one(
                    {'user_id': recipient['_id']},
                    session=mongo_session
                )
                
                if not recipient_account:
                    # Create a default account for recipient if none exists
                    acc_num = generate_account_number()
                    recipient_account = {
                        'account_number': acc_num,
                        'user_id': recipient['_id'],
                        'account_type': 'Savings',
                        'balance': 0.0,
                        'created_at': datetime.utcnow()
                    }
                    accounts_col.insert_one(recipient_account, session=mongo_session)
                
                # Calculate new balances
                new_sender_balance = sender_account['balance'] - amount
                new_recipient_balance = recipient_account['balance'] + amount
                
                # Update sender's balance
                accounts_col.update_one(
                    {'_id': sender_account['_id']},
                    {'$set': {'balance': new_sender_balance}},
                    session=mongo_session
                )
                
                # Update recipient's balance
                accounts_col.update_one(
                    {'_id': recipient_account['_id']},
                    {'$set': {'balance': new_recipient_balance}},
                    session=mongo_session
                )
                
                # Create transaction records for both sender and recipient
                transaction_time = datetime.utcnow()
                transaction_desc = purpose if purpose else f'GPay to {recipient["username"]}'
                
                # Sender's transaction record
                sender_transaction = {
                    'user_id': current_user['_id'],
                    'account_id': sender_account['_id'],
                    'account_number': sender_account['account_number'],  
                    'transaction_type': 'debit',
                    'amount': amount,
                    'balance_after': new_sender_balance,
                    'description': transaction_desc,
                    'to_upi': upi_id,
                    'created_at': transaction_time,
                    'status': 'completed'
                }
                
                # Recipient's transaction record
                recipient_transaction = {
                    'user_id': recipient['_id'],
                    'account_id': recipient_account['_id'],
                    'account_number': recipient_account['account_number'],  
                    'transaction_type': 'credit',
                    'amount': amount,
                    'balance_after': new_recipient_balance,
                    'description': f'GPay from {current_user["username"]}',
                    'from_upi': current_user.get('email', ''),
                    'created_at': transaction_time,
                    'status': 'completed'
                }
                
                # Insert both transactions
                transactions_col.insert_many([sender_transaction, recipient_transaction], session=mongo_session)
                
                # Commit the transaction
                mongo_session.commit_transaction()
                
                # Get updated sender's balance for the response
                updated_sender = accounts_col.find_one(
                    {'_id': sender_account['_id']},
                    session=mongo_session
                )
                
                return make_response(True, 
                    f'Payment of ₹{amount:.2f} to {recipient["username"]} completed successfully!',
                    data={
                        'new_balance': updated_sender['balance'],
                        'transaction_id': str(sender_transaction['_id'])
                    }
                )
                
            except Exception as e:
                # Abort transaction on error
                mongo_session.abort_transaction()
                print(f"Transaction failed: {str(e)}")
                return make_response(False, 'Transaction failed. Please try again.', str(e))
    
    # For GET requests, render the form
    if request.is_json:
        return jsonify({'success': False, 'error': 'Invalid request method'}), 400
    
    # Debug: List all collections in the database
    print("\n=== Database Collections ===")
    collections = client[_db_name].list_collection_names()
    print(f"Available collections: {collections}")
    
    # Debug: Count documents in each collection
    for coll_name in collections:
        try:
            count = client[_db_name][coll_name].count_documents({})
            print(f"Collection '{coll_name}': {count} documents")
        except Exception as e:
            print(f"Error counting documents in {coll_name}: {e}")
    
    # Get all users except the current user for the recipients list
    all_users = list(users_col.find(
        {'_id': {'$ne': current_user['_id']}},
        {'username': 1, 'email': 1, 'full_name': 1, '_id': 1}  # Include _id for debugging
    ))
    
    # Debug logging
    print(f"\n=== Current User ===")
    print(f"Username: {current_user.get('username')}")
    print(f"User ID: {current_user.get('_id')}")
    print(f"Email: {current_user.get('email', 'N/A')}")
    
    print(f"\n=== Found {len(all_users)} other users in the database ===")
    for idx, user in enumerate(all_users, 1):
        print(f"{idx}. ID: {user.get('_id')}")
        print(f"   Username: {user.get('username')}")
        print(f"   Email: {user.get('email', 'N/A')}")
        print(f"   Full Name: {user.get('full_name', 'N/A')}")
    
    # For GET requests, render the form with users
    upi_id = request.args.get('upi_id', '')
    amount = request.args.get('amount', '')
    
    return render_template('gpay_payment.html',
                         upi_id=upi_id,
                         amount=amount,
                         users=all_users)
    

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

# ---------------------------------------------------------------------------
# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    try:
        print(f"New client connected: {request.sid}")
        if 'user_id' in session:
            room = f"user_{session['user_id']}"
            join_room(room)
            print(f"Client {request.sid} joined room: {room}")
            return {'status': 'success', 'room': room}
        else:
            print("Unauthenticated connection attempt")
            return False  # Reject the connection if user is not authenticated
    except Exception as e:
        print(f"Error in handle_connect: {str(e)}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    try:
        print(f"Client disconnected: {request.sid}")
        if 'user_id' in session:
            room = f"user_{session['user_id']}"
            leave_room(room)
            print(f"Client {request.sid} left room: {room}")
    except Exception as e:
        print(f"Error in handle_disconnect: {str(e)}")

# Handle join room events from the client
@socketio.on('join')
def on_join(data):
    try:
        if 'user_id' in session and 'room' in data:
            room = data['room']
            join_room(room)
            print(f"Client {request.sid} joined room: {room}")
            return {'status': 'success', 'room': room}
        return {'status': 'error', 'message': 'Unauthorized'}
    except Exception as e:
        print(f"Error in on_join: {str(e)}")
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    try:
        port = int(os.environ.get('PORT', 5001))
        print(f"Starting PatternPay server on port {port}")
        print("Available on:")
        print(f"- http://localhost:{port}")
        print(f"- http://127.0.0.1:{port}")
        print("Press Ctrl+C to stop the server")
        
        # Run with Socket.IO support
        socketio.run(app, host='127.0.0.1', port=port, debug=True, use_reloader=True)
        
    except Exception as e:
        print(f"\nError starting server: {e}")
        print("\nTroubleshooting steps:")
        print(f"1. Make sure port {port} is not in use by another application")
        print("2. Try a different port number")
        print("3. Check your firewall settings")
        print("\nYou can specify a different port by running:")
        print(f"  set PORT=5050 && python patternpay_web.py")
