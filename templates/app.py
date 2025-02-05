from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_from_directory, abort, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
from threading import Thread
import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import FloatField, SubmitField, StringField
from wtforms.validators import InputRequired, NumberRange
from flask_migrate import Migrate
from threading import Lock
import string
import random
from random import choices
from string import ascii_letters, digits
from flask_mail import Message
from flask_mail import Mail
import secrets
from datetime import timedelta
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import or_, and_


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///26.db'
app.config['UPLOAD_FOLDER'] = 'uploads'  # Change to your desired upload folder
db = SQLAlchemy(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vintagevaults26@gmail.com'
app.config['MAIL_PASSWORD'] = 'bfds baum jurd rvbg'  # Replace with the generated App Password

mail = Mail(app)

def send_reset_email(recipient_email, reset_token):
    user = User.query.filter_by(email=recipient_email).first()
    if user:
        subject = 'Password Reset Request'
        sender = 'vintagevaults26@gmail.com'
        recipient = recipient_email
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        body = render_template('reset_password_email.html', user=user, reset_link=reset_link)

        message = Message(subject=subject, sender=sender, recipients=[recipient], html=body)
        mail.send(message)

def is_referral_code_valid(referrer_id):
    return User.query.filter_by(id=referrer_id).first() is not None

def is_user_id_valid(user_id):
    return User.query.filter_by(id=user_id).first() is not None

def get_user_balance(user_id):
    user = User.query.get(user_id)
    if user:
        return user.balance
    else:
        return None

def get_current_user_id():
    return current_user.id if current_user.is_authenticated else None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_sun20():
    return current_user.is_authenticated and current_user.id == 2 and current_user.username == 'sun20'

def get_miner(miner_id):
    return miners.get(miner_id)

def get_miner_by_id(miner_id):
    return miners.get(miner_id)

def is_logged_in():
    return current_user.is_authenticated

def is_referral_code_valid(referral_code):
    user = User.query.filter_by(referral_code=referral_code).first()
    if user:
        return True
    else:
        return False

def can_add_balance_to_user(user_id):
    user = User.query.get(user_id)
    if user.referrer:
        return True
    else:
        return False

def calculate_referral_commission(amount):
    commission = amount * 0.25
    return commission

def get_referrals(user_id):
    user = User.query.get(user_id)
    if user:
        referrals = User.query.filter_by(referrer_id=user_id).all()
        return referrals
    return []

def is_admin():
    return 'is_admin' in session and session['is_admin'] is True

def add_balance_to_user(user_id, amount):
    user = User.query.get(user_id)
    user.balance += amount
    db.session.commit()

    if user.referrer:
        commission = amount * 0.25
        user.referrer.balance += commission
        db.session.commit()
       
def generate_referral_code(length=8):
    characters = ascii_letters + digits
    while True:
        code = ''.join(choices(characters, k=length))
        # Check if the generated code already exists in the database
        if not db.session.query(User.query.filter_by(referral_code=code).exists()).scalar():
            break
    return code

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username is already in use. Please choose another.')

    # Custom validation for checking if the email is unique
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email is already registered. Please use a different email address.')

class WithdrawalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    wallet_address = db.Column(db.String(255), nullable=False)
    crypto_type = db.Column(db.String(50), nullable=False)  # New column for cryptocurrency type
    status = db.Column(db.String(20), nullable=False, default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class DepositRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(255), nullable=False)
    crypto_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='Pending', nullable=False)

    # Define relationships with User model
    from_user = db.relationship('User', foreign_keys=[from_user_id], back_populates='deposit_requests_sent')
    to_user = db.relationship('User', foreign_keys=[to_user_id], back_populates='deposit_requests_received')

    def update_status(self, new_status):
        self.status = new_status
        db.session.commit()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    referrer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    referrals = db.relationship('User', backref='referrer', remote_side=[id])
    miners = db.relationship('MinerPurchase', backref='user', lazy=True)
    referral_code = db.Column(db.String(50), unique=True, nullable=True, default=None)
    withdrawal_requests = db.relationship('WithdrawalRequest', backref='user', lazy=True)
    deposit_requests_sent = db.relationship('DepositRequest', foreign_keys='DepositRequest.from_user_id', back_populates='from_user')
    deposit_requests_received = db.relationship('DepositRequest', foreign_keys='DepositRequest.to_user_id', back_populates='to_user')
    
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f"<User {self.username}>"

class MinerPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    miner_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Miner:
    def __init__(self, id, price, percentage, shutdown_timer, interval):
        self.id = id
        self.price = price
        self.percentage = percentage
        self.shutdown_timer = shutdown_timer
        self.interval = interval
        self.running = True

balance_update_lock = Lock()

def miner_thread(miner, user_id):
    with app.app_context():
        user = User.query.get(user_id)
        while miner.running:
            time.sleep(miner.interval)
            with app.app_context():
                user = User.query.get(user_id)
                user.balance += miner.price * miner.percentage
                db.session.commit()
                print(f"Miner {miner.id} earned money. New balance: {user.balance}")

def shutdown_miner_thread(miner):
    time.sleep(miner.shutdown_timer)
    miner.running = False
    print(f"Miner {miner.id} has been shut down.")

user_balance = 1000
miner_data = [
    {"id": 1, "price": 100, "percentage": 0.1, "shutdown_timer": 50, "interval": 2},
    {"id": 2, "price": 150, "percentage": 0.15, "shutdown_timer": 100, "interval": 5},
    {"id": 3, "price": 200, "percentage": 0.2, "shutdown_timer": 120, "interval": 10},
    {"id": 4, "price": 500, "percentage": 0.5, "shutdown_timer": 300, "interval": 2}
]

# Routes

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

    def __repr__(self):
        return f"<ChatMessage {self.sender.username} to {self.receiver.username}: {self.content}>"


@app.route('/user_chat')
@login_required
def user_chat():
    messages = ChatMessage.query.filter_by(receiver_id=current_user.id).all()
    return render_template('user_chat.html', user=current_user, messages=messages)

@app.route('/customer_care_chat')
@login_required
def customer_care_chat():
    messages = ChatMessage.query.filter_by(sender_id=current_user.id).all()
    return render_template('customer_care_chat.html', user=current_user, messages=messages)

@socketio.on('user_message')
def handle_user_message(data):
    content = data['content']
    receiver_username = data['receiver_username']

    receiver = User.query.filter_by(username=receiver_username).first()
    if receiver:
        new_message = ChatMessage(sender=current_user, receiver=receiver, content=content)
        db.session.add(new_message)
        db.session.commit()

        # Broadcast the message to the specific user
        socketio.emit('user_message', {'content': content, 'sender_username': current_user.username}, room=receiver.id)

@socketio.on('customer_care_message')
def handle_customer_care_message(data):
    content = data['content']
    sender_username = data['sender_username']

    sender = User.query.filter_by(username=sender_username).first()
    if sender:
        new_message = ChatMessage(sender=current_user, receiver=sender, content=content)
        db.session.add(new_message)
        db.session.commit()

        # Broadcast the message to the specific user
        socketio.emit('customer_care_message', {'content': content, 'sender_username': current_user.username}, room=sender.id)

from flask import jsonify

# ... (previous code)

@app.route('/api/messages/<username>')
@login_required
def get_user_messages(username):
    sender = User.query.filter_by(username=username).first()
    if sender:
        messages = ChatMessage.query.filter_by(receiver_id=current_user.id, sender_id=sender.id).all()
        return jsonify([{'content': message.content, 'sender': message.sender.username} for message in messages])
    return jsonify([])

@app.route('/')
def index():
    return render_template('index.html')   

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Retrieve user's miner purchases
    user_purchases = MinerPurchase.query.filter_by(user_id=current_user.id).all()

    # Count the number of each miner purchased by the user
    miner_counts = {miner['id']: 0 for miner in miner_data}
    user_miners = {miner['id']: [] for miner in miner_data}

    # Populate user_miners and miner_counts based on purchases
    for purchase in user_purchases:
        miner_counts[purchase.miner_id] += 1
        user_miners[purchase.miner_id].append(purchase)

    # Render the dashboard template with relevant data, including user balance
    return render_template('dashboard.html', balance=current_user.balance, miners=miner_data, miner_counts=miner_counts, user_miners=user_miners)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        referrer_id = request.form.get('referrer_id')
        referral_code = request.form.get('referral_code', generate_referral_code())

        try:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email is already registered. Please use a different email address.', 'danger')
                return render_template('register.html')

            # Check if username length is more than 10
            if len(username) > 10:
                flash('Username should be at most 10 characters long.', 'danger')
                return render_template('register.html')

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=6)
            new_user = User(username=username, email=email, password=hashed_password, balance=0.0, referral_code=referral_code)

            if referrer_id:
                referrer = User.query.get(referrer_id)
                if referrer:
                    referrer.balance += 10.0
                    db.session.commit()
                new_user.referrer_id = referrer_id

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash('Registration successful. You are now logged in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration failed. {str(e)}', 'danger')

    return render_template('register.html')

@app.context_processor
def inject_flash_messages():
    def clear_flash_messages():
        if '_flashes' in session:
            session['_flashes'] = []
    return dict(clear_flash_messages=clear_flash_messages, flashes=get_flashed_messages)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'email' in request.form and 'password' in request.form:
            email = request.form['email']
            password = request.form['password']

            user = User.query.filter_by(email=email).first()

            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    flash('Login successful.', 'login-success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Incorrect password. Please try again.', 'login-error')
                    return redirect(url_for('login'))  # Redirect to login to avoid form resubmission
            else:
                flash('User not found. Please check your email and try again.', 'login-error')
                return redirect(url_for('login'))  # Redirect to login to avoid form resubmission
        else:
            flash('Invalid form data. Please make sure to provide both email and password.', 'login-error')

    # Clear flash messages after rendering the template
    flash_messages = get_flashed_messages(with_categories=True)
    session['_flashes'] = []  # Clear flashes to prevent persistence

    return render_template('login.html', messages=flash_messages)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/purchase_miner', methods=['POST'])
@login_required
def purchase_miner():
    miner_id = int(request.json.get('miner_id', 1))
    selected_miner = next((miner for miner in miner_data if miner['id'] == miner_id), None)

    if selected_miner and current_user.balance >= selected_miner['price']:
        current_user.balance -= selected_miner['price']

        new_miner_purchase = MinerPurchase(user=current_user, miner_id=miner_id)
        db.session.add(new_miner_purchase)
        db.session.commit()

        new_miner = Miner(
            id=selected_miner['id'],
            price=selected_miner['price'],
            percentage=selected_miner['percentage'],
            shutdown_timer=selected_miner['shutdown_timer'],
            interval=selected_miner['interval']
        )

        miner_thread_instance = Thread(target=miner_thread, args=(new_miner, current_user.id))
        miner_thread_instance.daemon = True
        miner_thread_instance.start()

        shutdown_thread = Thread(target=shutdown_miner_thread, args=(new_miner,))
        shutdown_thread.daemon = True
        shutdown_thread.start()

        db.session.commit()
        updated_balance = User.query.get(current_user.id).balance

        return jsonify({'success': True, 'miner_id': new_miner.id, 'balance': updated_balance})
    else:
        return jsonify({'success': False, 'message': 'Insufficient balance or invalid miner selection'})

@app.route('/add_balance', methods=['GET', 'POST'])
def add_balance():
    if not is_sun20():
        flash('Unauthorized. Only user "sun20" with ID 2 can access this page.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user_id = int(request.form['user_id'])
        amount = float(request.form['amount'])
        user = User.query.get(user_id)
        
        if user:
            referrer_id = user.referrer_id

            if referrer_id:
                referrer = User.query.get(referrer_id)
                referral_bonus = 0.25 * amount
                
                if referrer:
                    referrer.balance += referral_bonus
                    db.session.commit()
                    flash(f'Referral bonus of ${referral_bonus} added to your referrer\'s balance.', 'success')
                else:
                    flash('User has no referrer.', 'info')

            user.balance += amount
            db.session.commit()
            flash(f'Added ${amount} to user with ID {user_id}\'s balance', 'success')
        else:
            flash(f'User with ID {user_id} not found', 'danger')

    return render_template('add_balance.html')

@app.route('/referral_link')
@login_required
def referral_link():
    user = current_user
    referrals = User.query.filter_by(referrer_id=user.id).all()
    referral_link = f'http://127.0.0.1:5000/register?referrer_id={user.id}&referral_code={user.referral_code}'
    return render_template('referral_link.html', referral_link=referral_link, referrals=referrals, user=user)


# Dummy data for demonstration purposes
withdrawal_requests = []
user_id_counter = 1  # Counter for generating unique user IDs

# Dummy function to represent your notification mechanism
def send_notification(user_id, message):
    # Replace this with your actual notification method
    print(f"Sending permanent notification to user {user_id}: {message}")

@app.route('/withdraw-form', methods=['GET'])
@login_required
def withdrawal_form():
    # Fetch the current user's previous withdrawal details from the database
    user_withdrawals = current_user.withdrawal_requests

    return render_template('withdraw_form.html', user=current_user, user_withdrawals=user_withdrawals)

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    # Get withdrawal details from the request
    user_id = current_user.id
    withdrawal_amount = float(request.form.get('amount'))
    wallet_address = request.form.get('wallet_address')
    crypto_type = request.form.get('crypto_type')  # Get cryptocurrency type from the form

    # Fetch the user with the given ID
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Check if the user has sufficient balance
    if user.balance < withdrawal_amount:
        return jsonify({'message': 'Insufficient balance'}), 400

    # Check if the user has purchased a miner
    if not user.miners:
        return jsonify({'message': 'No miner purchased. Purchase a miner to withdraw'}), 400

    # Check if the withdrawal amount meets the minimum requirement
    if withdrawal_amount < 2000:
        return jsonify({'message': 'Minimum withdrawal amount is 2000'}), 400

    # Perform withdrawal logic here
    user.balance -= withdrawal_amount

    # Save the withdrawal request details to the database with a pending status
    withdrawal_request = WithdrawalRequest(
        user_id=user.id,
        amount=withdrawal_amount,
        wallet_address=wallet_address,
        crypto_type=crypto_type,  # Add cryptocurrency type to the WithdrawalRequest object
        status='Pending'
    )
    db.session.add(withdrawal_request)
    db.session.commit()

    # Send a permanent notification to the user
    notification_message = f"Withdrawal request received: {withdrawal_amount} {crypto_type} to {wallet_address}"
    send_notification(user.id, notification_message)

    return redirect(url_for('withdrawal_confirmation'))

@app.route('/withdrawal-confirmation', methods=['GET'])
@login_required
def withdrawal_confirmation():
    return render_template('withdrawal_confirmation.html')

@app.route('/admin/withdraw-requests', methods=['GET'])
@login_required
def admin_withdraw_requests():
    admin_user_id = 2  # Replace with the actual admin user ID

    # Check if the current user is the admin
    if current_user.id != admin_user_id:
        abort(403)  # HTTP status code for forbidden access

    # Fetch withdrawal requests from the database
    withdrawal_requests = WithdrawalRequest.query.all()

    return render_template('withdraw_requests.html', withdrawal_requests=withdrawal_requests)

@app.route('/approve-withdrawal/<int:request_id>', methods=['POST'])
@login_required
def approve_withdrawal(request_id):
    admin_user_id = 2  # Replace with the actual admin user ID

    # Check if the current user is the admin
    if current_user.id != admin_user_id:
        abort(403)  # HTTP status code for forbidden access

    # Fetch the withdrawal request from the database
    withdrawal_request = WithdrawalRequest.query.get(request_id)

    if not withdrawal_request:
        return jsonify({'message': 'Withdrawal request not found'}), 404

    # Update the status to 'Approved'
    withdrawal_request.status = 'Approved'
    db.session.commit()

    return redirect(url_for('admin_withdraw_requests'))


@app.route('/reject-withdrawal/<int:request_id>', methods=['POST'])
@login_required
def reject_withdrawal(request_id):
    admin_user_id = 2  # Replace with the actual admin user ID

    # Check if the current user is the admin
    if current_user.id != admin_user_id:
        abort(403)  # HTTP status code for forbidden access

    # Fetch the withdrawal request from the database
    withdrawal_request = WithdrawalRequest.query.get(request_id)

    if not withdrawal_request:
        return jsonify({'message': 'Withdrawal request not found'}), 404

    # Update the status to 'Rejected'
    withdrawal_request.status = 'Rejected'
    db.session.commit()

    return redirect(url_for('admin_withdraw_requests'))

@app.route('/deposit-form', methods=['GET', 'POST'])
@login_required
def deposit_form():
    if request.method == 'POST':
        # Handle form submission
        user_id = current_user.id
        to_user_id = request.form.get('to_user_id')
        amount = float(request.form.get('amount'))
        transaction_id = request.form.get('transaction_id')
        crypto_type = request.form.get('crypto_type')

        if amount < 2000:
            return jsonify({'message': 'Minimum deposit amount is 2000'}), 400

        # Create a new deposit request
        deposit_request = DepositRequest(
            from_user_id=user_id,
            to_user_id=to_user_id,
            amount=amount,
            transaction_id=transaction_id,
            crypto_type=crypto_type
        )

        db.session.add(deposit_request)
        db.session.commit()

        return redirect(url_for('deposit_confirmation'))

    # Render the deposit form template for GET requests
    return render_template('deposit_form.html', user=current_user)

@app.route('/admin/approve-deposit/<int:deposit_id>', methods=['POST'])
@login_required
def approve_deposit(deposit_id):
    admin_user_id = 2  # Replace with the actual admin user ID

    if current_user.id != admin_user_id:
        abort(403)

    deposit_request = DepositRequest.query.get_or_404(deposit_id)
    deposit_request.update_status('Approved')

    return redirect(url_for('admin_deposit_requests'))

@app.route('/admin/reject-deposit/<int:deposit_id>', methods=['POST'])
@login_required
def reject_deposit(deposit_id):
    admin_user_id = 2  # Replace with the actual admin user ID

    if current_user.id != admin_user_id:
        abort(403)

    deposit_request = DepositRequest.query.get_or_404(deposit_id)
    deposit_request.update_status('Rejected')

    return redirect(url_for('admin_deposit_requests'))

@app.route('/deposit-confirmation', methods=['GET'])
@login_required
def deposit_confirmation():
    return render_template('deposit_confirmation.html')

@app.route('/admin/deposit-requests', methods=['GET'])
@login_required
def admin_deposit_requests():
    admin_user_id = 2  # Replace with the actual admin user ID

    # Check if the current user is the admin
    if current_user.id != admin_user_id:
        abort(403)

    # Fetch deposit requests from the database
    deposit_requests = DepositRequest.query.all()

    return render_template('deposit_requests.html', deposit_requests=deposit_requests)

@app.route('/profile')
@login_required
def profile():
    user = current_user
    return render_template('profile.html', user=user)

@app.route('/history')
@login_required
def transaction_history():
    # Fetch user's miner purchases
    user_purchases = MinerPurchase.query.filter_by(user_id=current_user.id).all()

    # Fetch user's withdrawal requests
    withdrawal_requests = WithdrawalRequest.query.filter_by(user_id=current_user.id).all()

    # Fetch user's deposit requests where the current user is the sender (from_user_id)
    deposit_requests_sent = DepositRequest.query.filter_by(from_user_id=current_user.id).all()

    # Fetch user's deposit requests where the current user is the recipient (to_user_id)
    deposit_requests_received = DepositRequest.query.filter_by(to_user_id=current_user.id).all()

    return render_template('transaction_history.html', user_purchases=user_purchases,
                           withdrawal_requests=withdrawal_requests,
                           deposit_requests_sent=deposit_requests_sent,
                           deposit_requests_received=deposit_requests_received)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a unique token and store it in the database
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
            db.session.commit()

            # Send the reset link to the user's email
            send_reset_email(user.email, token)

            flash('An email with instructions to reset your password has been sent. Please check your email.', 'reset-password-instruction')
            return redirect(url_for('forgot_password'))
        else:
            flash('Email not found. Please check and try again.', 'forgot-password-error')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if user and user.reset_token_expiration > datetime.utcnow():
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=6)

            # Update the user's password and reset the token
            user.password = hashed_password
            user.reset_token = None
            user.reset_token_expiration = None
            db.session.commit()

            flash('Password reset successful. You can now log in with your new password.', 'reset-password-success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)
    else:
        flash('Invalid or expired reset token. Please try again.', 'reset-password-error')
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        socketio.run(app,port=5000, debug=True)  # Run Flask app on port 5000

