"""PatternPay Flask app backed by MongoDB Atlas.
This replaces the previous SQLAlchemy/SQLite implementation.
"""
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from bson.objectid import ObjectId
import random
import os

# Local helper that exposes users_col, accounts_col, transactions_col
from db import users_col, accounts_col, transactions_col, client  # type: ignore

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'patternpay-secret')

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

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
    
    # Get recent transactions
    recent_transactions = list(transactions_col.find({
        '$or': [
            {'from_account': {'$in': [acc['account_number'] for acc in user_accounts]}},
            {'to_account': {'$in': [acc['account_number'] for acc in user_accounts]}}
        ]
    }).sort('timestamp', -1).limit(5))
    
    # Store user's socket room in session
    if 'socket_room' not in session:
        session['socket_room'] = f"user_{session['user_id']}"
    
    total_balance = sum(acc['balance'] for acc in user_accounts)
    
    return render_template('dashboard.html', 
                         user=user, 
                         accounts=user_accounts,
                         transactions=recent_transactions,
                         socket_room=session['socket_room'],
                         total_balance=total_balance)


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


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        from_account = request.form.get('from_account')
        to_account = request.form.get('to_account')
        amount = float(request.form.get('amount', 0))
        description = request.form.get('description', '')
        
        # Validate accounts and balance
        source = accounts_col.find_one({
            'account_number': from_account,
            'user_id': ObjectId(session['user_id'])
        })
        
        if not source:
            flash('Source account not found', 'error')
            return redirect(url_for('transfer'))
            
        if source['balance'] < amount:
            flash('Insufficient funds', 'error')
            return redirect(url_for('transfer'))
            
        destination = accounts_col.find_one({'account_number': to_account})
        if not destination:
            flash('Destination account not found', 'error')
            return redirect(url_for('transfer'))
        
        # Start transaction
        with client.start_session() as session_client:
            with session_client.start_transaction():
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
                    'status': 'completed'
                }
                transactions_col.insert_one(transaction, session=session_client)
                
                session_client.commit_transaction()
                
                flash('Transfer successful!', 'success')
                
                # Notify both sender and receiver in real-time
                socketio.emit('balance_update', {
                    'account_number': from_account,
                    'new_balance': source['balance'] - amount
                }, room=f"user_{session['user_id']}")
                
                if str(destination['user_id']) != session['user_id']:
                    socketio.emit('balance_update', {
                        'account_number': to_account,
                        'new_balance': destination['balance'] + amount
                    }, room=f"user_{str(destination['user_id'])}")
                    
                    socketio.emit('new_transaction', {
                        'message': f'Received ₹{amount:.2f} from {source["account_number"][-4:]}',
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=f"user_{str(destination['user_id'])}")
                
                return redirect(url_for('dashboard'))
    
    user_accounts = list(accounts_col.find({'user_id': ObjectId(session['user_id'])}))
    return render_template('transfer.html', accounts=user_accounts)


@app.route('/upi_payment', methods=['GET', 'POST'])
def upi_payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        upi_id = request.form['upi_id']
        amount = float(request.form['amount'])

        transactions_col.insert_one({
            'account_number': 'UPI',
            'transaction_type': 'UPI Payment',
            'amount': amount,
            'description': f'UPI payment to {upi_id}',
            'created_at': datetime.utcnow(),
        })
        flash(f'UPI Payment successful! Amount: ${amount} to {upi_id}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upi_payment.html')


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
    return render_template('settings.html')

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
    
    # Get current user
    current_user = users_col.find_one({'username': session['username']})
    if not current_user:
        if request.is_json:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
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
        
    return render_template('gpay_payment.html',
                         upi_id=request.args.get('upi_id', ''),
                         amount=request.args.get('amount', ''),
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
    if 'user_id' in session:
        room = f"user_{session['user_id']}"
        join_room(room)
        print(f"Client connected to room: {room}")

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        room = f"user_{session['user_id']}"
        leave_room(room)
        print(f"Client disconnected from room: {room}")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0')
