import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db') # Change to your actual .db file name
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, date, timedelta
from functools import wraps
from markupsafe import escape as markup_escape

app = Flask(__name__)

# Behind a hosting proxy (Render etc.): trust X-Forwarded-* so HTTPS and client IPs are correct
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

try:
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, IntegerField, DecimalField, SelectField, DateField, TimeField
    from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp, ValidationError
    from wtforms.validators import InputRequired
    WTF_CSRF_ENABLED = True
except ImportError:
    WTF_CSRF_ENABLED = False
    FlaskForm = object

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['WTF_CSRF_ENABLED'] = WTF_CSRF_ENABLED

MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPTS = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def sanitize_input(text, max_length=255):
    if text is None:
        return None
    text = str(text).strip()
    text = markup_escape(text)
    return str(text)[:max_length]

def validate_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone_format(phone):
    if not phone:
        return True
    pattern = r'^01[0-9]{9}$'
    return re.match(pattern, phone.replace(' ', '').replace('-', '')) is not None

def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login first.', 'warning')
                return redirect(url_for('login'))
            if session.get('user_role') != role:
                flash('Access denied.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"
    return response

@app.errorhandler(404)
def not_found(error):
    flash('Page not found.', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    flash('An internal error occurred. Please try again later.', 'danger')
    return redirect(url_for('index'))

@app.template_filter('escape_html')
def escape_html_filter(text):
    return markup_escape(text) if text else ''

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(32).hex()
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/')
def index():
    conn = get_db()
    cities = conn.execute('SELECT * FROM cities ORDER BY name').fetchall()
    conn.close()
    today_str = date.today().isoformat()
    return render_template('index.html', cities=cities, today=today_str)

@app.route('/search', methods=['POST'])
def search():
    if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
        flash('Invalid request. Please try again.', 'danger')
        return redirect(url_for('index'))

    from_city = sanitize_input(request.form.get('from_city'))
    to_city = sanitize_input(request.form.get('to_city'))
    travel_date = sanitize_input(request.form.get('travel_date'), max_length=10)

    if not all([from_city, to_city, travel_date]):
        flash('Please fill in all search fields.', 'danger')
        return redirect(url_for('index'))

    if not travel_date.match(r'^\d{4}-\d{2}-\d{2}$') if hasattr(travel_date, 'match') else True:
        date_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
        if not date_pattern.match(travel_date):
            flash('Invalid date format.', 'danger')
            return redirect(url_for('index'))

    try:
        datetime.strptime(travel_date, '%Y-%m-%d')
    except ValueError:
        flash('Invalid travel date.', 'danger')
        return redirect(url_for('index'))

    conn = get_db()
    cities = conn.execute('SELECT * FROM cities ORDER BY name').fetchall()

    if not from_city.isdigit() or not to_city.isdigit():
        flash('Invalid city selection.', 'danger')
        conn.close()
        return redirect(url_for('index'))

    trips = conn.execute('''
        SELECT
            trips.id,
            trips.travel_date,
            trips.departure_time,
            trips.arrival_time,
            trips.price,
            trips.available_seats,
            c1.name as from_city,
            c2.name as to_city,
            buses.bus_name,
            buses.bus_type
        FROM trips
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        WHERE trips.from_city_id = ?
          AND trips.to_city_id = ?
          AND trips.travel_date = ?
          AND trips.available_seats > 0
        ORDER BY trips.departure_time
    ''', (int(from_city), int(to_city), travel_date)).fetchall()

    conn.close()
    return render_template('search_results.html', trips=trips, cities=cities)

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr

    if client_ip in LOGIN_ATTEMPTS and LOGIN_ATTEMPTS[client_ip]['count'] >= MAX_LOGIN_ATTEMPTS:
        if datetime.now() - LOGIN_ATTEMPTS[client_ip]['last_attempt'] < timedelta(minutes=15):
            flash('Too many login attempts. Please try again in 15 minutes.', 'danger')
            return render_template('login.html')

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            return render_template('login.html')

        email = sanitize_input(request.form.get('email'), max_length=255)
        password = request.form.get('password', '')

        if not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return render_template('login.html')

        if not validate_email_format(email):
            flash('Invalid email format.', 'danger')
            return render_template('login.html')

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            LOGIN_ATTEMPTS[client_ip] = {'count': 0, 'last_attempt': datetime.now()}

            session['user_id'] = user['id']
            session['user_name'] = markup_escape(user['full_name'])
            session['user_role'] = user['role']
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=2)
            flash('Login successful!', 'success')

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            if client_ip in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[client_ip]['count'] += 1
                LOGIN_ATTEMPTS[client_ip]['last_attempt'] = datetime.now()
            else:
                LOGIN_ATTEMPTS[client_ip] = {'count': 1, 'last_attempt': datetime.now()}

            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            return redirect(url_for('register'))

        full_name = sanitize_input(request.form.get('full_name'), max_length=100)
        email = sanitize_input(request.form.get('email'), max_length=255)
        password = request.form.get('password', '')
        phone = sanitize_input(request.form.get('phone'), max_length=20)

        if not full_name or not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('register'))

        if not validate_email_format(email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        is_strong, msg = validate_password_strength(password)
        if not is_strong:
            flash(msg, 'warning')
            return redirect(url_for('register'))

        if phone and not validate_phone_format(phone):
            flash('Invalid phone number format. Use Egyptian format (01xxxxxxxxx).', 'warning')
            return redirect(url_for('register'))

        if len(full_name) < 2:
            flash('Name must be at least 2 characters.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = get_db()
        try:
            conn.execute('''
                INSERT INTO users (full_name, email, password, phone, role)
                VALUES (?, ?, ?, ?, 'customer')
            ''', (markup_escape(full_name), email.lower(), hashed_password, markup_escape(phone) if phone else None))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists. Please use a different email.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/customer/dashboard')
@login_required
@role_required('customer')
def customer_dashboard():
    conn = get_db()
    cities = conn.execute('SELECT * FROM cities ORDER BY name').fetchall()
    conn.close()
    today_str = date.today().isoformat()
    return render_template('customer_dashboard.html', cities=cities, today=today_str)

@app.route('/customer/search', methods=['POST'])
@login_required
@role_required('customer')
def customer_search():
    if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
        flash('Invalid request. Please try again.', 'danger')
        return redirect(url_for('customer_dashboard'))

    from_city = sanitize_input(request.form.get('from_city'))
    to_city = sanitize_input(request.form.get('to_city'))
    travel_date = sanitize_input(request.form.get('travel_date'), max_length=10)

    if not all([from_city, to_city, travel_date]):
        flash('Please fill in all search fields.', 'danger')
        return redirect(url_for('customer_dashboard'))

    if not from_city.isdigit() or not to_city.isdigit():
        flash('Invalid city selection.', 'danger')
        return redirect(url_for('customer_dashboard'))

    try:
        datetime.strptime(travel_date, '%Y-%m-%d')
    except ValueError:
        flash('Invalid travel date.', 'danger')
        return redirect(url_for('customer_dashboard'))

    conn = get_db()
    cities = conn.execute('SELECT * FROM cities ORDER BY name').fetchall()

    trips = conn.execute('''
        SELECT
            trips.id,
            trips.travel_date,
            trips.departure_time,
            trips.arrival_time,
            trips.price,
            trips.available_seats,
            c1.name as from_city,
            c2.name as to_city,
            buses.bus_name,
            buses.bus_type
        FROM trips
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        WHERE trips.from_city_id = ?
          AND trips.to_city_id = ?
          AND trips.travel_date = ?
          AND trips.available_seats > 0
        ORDER BY trips.departure_time
    ''', (int(from_city), int(to_city), travel_date)).fetchall()

    conn.close()
    return render_template('search_results.html', trips=trips, cities=cities)

@app.route('/book/<int:trip_id>', methods=['GET', 'POST'])
@login_required
@role_required('customer')
def book_ticket(trip_id):
    if trip_id <= 0:
        flash('Invalid trip.', 'danger')
        return redirect(url_for('customer_dashboard'))

    conn = get_db()

    trip = conn.execute('''
        SELECT
            trips.*,
            c1.name as from_city,
            c2.name as to_city,
            buses.bus_name,
            buses.bus_type
        FROM trips
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        WHERE trips.id = ?
    ''', (trip_id,)).fetchone()

    if not trip:
        flash('Trip not found.', 'danger')
        conn.close()
        return redirect(url_for('customer_dashboard'))

    payment_methods = conn.execute(
        'SELECT * FROM payment_methods WHERE is_active = 1 ORDER BY id'
    ).fetchall()

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            conn.close()
            return redirect(url_for('book_ticket', trip_id=trip_id))

        try:
            seats_count = int(request.form.get('seats_count', 0))
            payment_method_id = int(request.form.get('payment_method', 0))
        except (ValueError, TypeError):
            flash('Invalid input.', 'danger')
            conn.close()
            return redirect(url_for('book_ticket', trip_id=trip_id))

        if seats_count < 1 or seats_count > trip['available_seats']:
            flash(f'Please select between 1 and {trip["available_seats"]} seats.', 'danger')
            conn.close()
            return redirect(url_for('book_ticket', trip_id=trip_id))

        valid_payment = any(pm['id'] == payment_method_id for pm in payment_methods)
        if not valid_payment:
            flash('Invalid payment method.', 'danger')
            conn.close()
            return redirect(url_for('book_ticket', trip_id=trip_id))

        total_price = seats_count * float(trip['price'])

        session['pending_booking'] = {
            'trip_id': trip_id,
            'seats_count': seats_count,
            'total_price': total_price,
            'payment_method_id': payment_method_id
        }

        conn.close()
        return redirect(url_for('process_payment'))

    conn.close()
    return render_template('book_ticket.html', trip=trip, payment_methods=payment_methods)

@app.route('/payment', methods=['GET', 'POST'])
@login_required
@role_required('customer')
def process_payment():
    if 'pending_booking' not in session:
        flash('No pending booking found.', 'warning')
        return redirect(url_for('customer_dashboard'))

    pending = session['pending_booking']
    trip_id = pending['trip_id']
    seats_count = pending['seats_count']
    total_price = pending['total_price']
    payment_method_id = pending['payment_method_id']

    conn = get_db()

    trip = conn.execute('''
        SELECT
            trips.*,
            c1.name as from_city,
            c2.name as to_city,
            buses.bus_name,
            buses.bus_type
        FROM trips
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        WHERE trips.id = ?
    ''', (trip_id,)).fetchone()

    if not trip:
        flash('Trip not found.', 'danger')
        del session['pending_booking']
        conn.close()
        return redirect(url_for('customer_dashboard'))

    payment_method = conn.execute(
        'SELECT * FROM payment_methods WHERE id = ?', (payment_method_id,)
    ).fetchone()

    if not payment_method:
        flash('Invalid payment method.', 'danger')
        del session['pending_booking']
        conn.close()
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            conn.close()
            return render_template('payment.html', trip=trip, payment_method=payment_method,
                                   total_price=total_price, seats_count=seats_count)

        payment_data = {}

        if payment_method_id == 1:
            payment_data['transaction_id'] = 'CASH-' + datetime.now().strftime('%Y%m%d%H%M%S')
            payment_status = 'Completed'

        elif payment_method_id in [2, 4]:
            card_number = sanitize_input(request.form.get('card_number', '').replace(' ', ''), max_length=19)
            card_holder = sanitize_input(request.form.get('card_holder', ''), max_length=100)
            expiry_date = sanitize_input(request.form.get('expiry_date', ''), max_length=7)
            cvv = sanitize_input(request.form.get('cvv', ''), max_length=4)

            if not card_number or len(card_number) < 12 or len(card_number) > 19:
                flash('Invalid card number.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            if not card_holder or not expiry_date or not cvv:
                flash('Please fill in all card details.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            if not cvv.isdigit() or len(cvv) < 3:
                flash('Invalid CVV.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            expiry_pattern = re.compile(r'^(0[1-9]|1[0-2])\/20\d{2}$')
            if not expiry_pattern.match(expiry_date):
                flash('Invalid expiry date format (MM/YYYY).', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            month, year = expiry_date.split('/')
            exp_year = int(year)
            exp_month = int(month)
            current_year = datetime.now().year
            current_month = datetime.now().month

            if exp_year < current_year or (exp_year == current_year and exp_month < current_month):
                flash('Card has expired.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            masked_card = 'XXXX-XXXX-XXXX-' + card_number[-4:]
            payment_data['transaction_id'] = f'CARD-{payment_method["name"][:3].upper()}-{datetime.now().strftime("%Y%m%d%H%M%S")}'
            payment_data['card_last_four'] = card_number[-4:]
            payment_status = 'Completed'

        elif payment_method_id == 3:
            fawry_reference = sanitize_input(request.form.get('fawry_reference', ''), max_length=30)

            if not fawry_reference or len(fawry_reference) < 10:
                flash('Invalid Fawry reference number.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            if not re.match(r'^[A-Za-z0-9]+$', fawry_reference):
                flash('Invalid Fawry reference format.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            payment_data['transaction_id'] = f'FAWRY-{datetime.now().strftime("%Y%m%d%H%M%S")}'
            payment_data['fawry_reference'] = fawry_reference
            payment_status = 'Completed'

        elif payment_method_id == 5:
            wallet_number = sanitize_input(request.form.get('wallet_number', ''), max_length=15)

            if not wallet_number or len(wallet_number) < 10:
                flash('Invalid wallet number.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            wallet_pattern = re.compile(r'^01[0-9]{9}$')
            if not wallet_pattern.match(wallet_number.replace(' ', '').replace('-', '')):
                flash('Invalid wallet number format.', 'danger')
                conn.close()
                return render_template('payment.html', trip=trip, payment_method=payment_method,
                                       total_price=total_price, seats_count=seats_count)

            payment_data['transaction_id'] = f'WALLET-{datetime.now().strftime("%Y%m%d%H%M%S")}'
            payment_data['wallet_number'] = wallet_number
            payment_status = 'Completed'

        else:
            flash('Invalid payment method.', 'danger')
            conn.close()
            return redirect(url_for('book_ticket', trip_id=trip_id))

        payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        booking_date = date.today().isoformat()

        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO payments (method_id, amount, transaction_id, payment_date, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (payment_method_id, total_price, payment_data['transaction_id'], payment_date, payment_status))
            payment_id = cursor.lastrowid

            cursor.execute('''
                INSERT INTO bookings (user_id, trip_id, seats_count, total_price, booking_date, status, payment_id)
                VALUES (?, ?, ?, ?, ?, 'Confirmed', ?)
            ''', (session['user_id'], trip_id, seats_count, total_price, booking_date, payment_id))

            conn.execute('''
                UPDATE trips SET available_seats = available_seats - ? WHERE id = ?
            ''', (seats_count, trip_id))

            conn.commit()

            del session['pending_booking']

            flash('Payment successful! Your booking is confirmed.', 'success')
            conn.close()
            return redirect(url_for('my_bookings'))

        except Exception as e:
            conn.rollback()
            flash('An error occurred during payment. Please try again.', 'danger')
            conn.close()
            return render_template('payment.html', trip=trip, payment_method=payment_method,
                                   total_price=total_price, seats_count=seats_count)

    conn.close()
    return render_template('payment.html', trip=trip, payment_method=payment_method,
                          total_price=total_price, seats_count=seats_count)

@app.route('/payment/cancel')
def payment_cancel():
    if 'pending_booking' in session:
        del session['pending_booking']
    flash('Payment cancelled. Your booking has not been processed.', 'info')
    return redirect(url_for('customer_dashboard'))

@app.route('/my_bookings')
@login_required
@role_required('customer')
def my_bookings():
    conn = get_db()
    bookings = conn.execute('''
        SELECT
            bookings.*,
            c1.name as from_city,
            c2.name as to_city,
            trips.travel_date,
            trips.departure_time,
            trips.arrival_time,
            buses.bus_name,
            buses.bus_type,
            payments.transaction_id,
            payments.payment_date,
            payment_methods.name as payment_method
        FROM bookings
        JOIN trips ON bookings.trip_id = trips.id
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        LEFT JOIN payments ON bookings.payment_id = payments.id
        LEFT JOIN payment_methods ON payments.method_id = payment_methods.id
        WHERE bookings.user_id = ?
        ORDER BY bookings.booking_date DESC, bookings.id DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('my_bookings.html', bookings=bookings)

@app.route('/cancel_booking/<int:booking_id>', methods=['GET', 'POST'])
@login_required
@role_required('customer')
def cancel_booking(booking_id):
    if booking_id <= 0:
        flash('Invalid booking.', 'danger')
        return redirect(url_for('my_bookings'))

    conn = get_db()

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            conn.close()
            return redirect(url_for('my_bookings'))

    booking = conn.execute('''
        SELECT * FROM bookings WHERE id = ? AND user_id = ?
    ''', (booking_id, session['user_id'])).fetchone()

    if not booking:
        flash('Booking not found.', 'danger')
        conn.close()
        return redirect(url_for('my_bookings'))

    if booking['status'] == 'Cancelled':
        flash('Booking is already cancelled.', 'warning')
        conn.close()
        return redirect(url_for('my_bookings'))

    trip = conn.execute('SELECT * FROM trips WHERE id = ?', (booking['trip_id'],)).fetchone()
    trip_date = datetime.strptime(trip['travel_date'], '%Y-%m-%d').date()

    if trip_date < date.today():
        flash('Cannot cancel a past trip.', 'danger')
        conn.close()
        return redirect(url_for('my_bookings'))

    conn.execute('''
        UPDATE bookings SET status = 'Cancelled' WHERE id = ?
    ''', (booking_id,))

    conn.execute('''
        UPDATE trips SET available_seats = available_seats + ? WHERE id = ?
    ''', (booking['seats_count'], booking['trip_id']))

    conn.commit()
    conn.close()

    flash('Booking cancelled successfully.', 'success')
    return redirect(url_for('my_bookings'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    conn = get_db()

    total_trips = conn.execute('SELECT COUNT(*) as count FROM trips').fetchone()['count']
    total_bookings = conn.execute('SELECT COUNT(*) as count FROM bookings').fetchone()['count']
    total_customers = conn.execute(
        "SELECT COUNT(*) as count FROM users WHERE role = 'customer'"
    ).fetchone()['count']

    revenue = conn.execute('''
        SELECT COALESCE(SUM(total_price), 0) as total
        FROM bookings
        WHERE status = 'Confirmed'
    ''').fetchone()['total']

    conn.close()

    return render_template(
        'admin_dashboard.html',
        total_trips=total_trips,
        total_bookings=total_bookings,
        total_customers=total_customers,
        revenue=revenue
    )

@app.route('/admin/cities', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_cities():
    conn = get_db()

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            conn.close()
            return redirect(url_for('manage_cities'))

        action = sanitize_input(request.form.get('action'))

        if action == 'add':
            name = sanitize_input(request.form.get('name'), max_length=100)
            if not name or len(name) < 2:
                flash('City name must be at least 2 characters.', 'warning')
                conn.close()
                return redirect(url_for('manage_cities'))

            if not re.match(r'^[A-Za-z\s\'-]+$', name):
                flash('City name contains invalid characters.', 'warning')
                conn.close()
                return redirect(url_for('manage_cities'))

            try:
                conn.execute('INSERT INTO cities (name) VALUES (?)', (name,))
                conn.commit()
                flash('City added successfully.', 'success')
            except sqlite3.IntegrityError:
                flash('City already exists.', 'warning')

        elif action == 'edit':
            city_id = sanitize_input(request.form.get('city_id'), max_length=10)
            name = sanitize_input(request.form.get('name'), max_length=100)

            if not city_id or not city_id.isdigit():
                flash('Invalid city ID.', 'danger')
                conn.close()
                return redirect(url_for('manage_cities'))

            if not name or len(name) < 2:
                flash('City name must be at least 2 characters.', 'warning')
                conn.close()
                return redirect(url_for('manage_cities'))

            try:
                conn.execute('UPDATE cities SET name = ? WHERE id = ?', (name, int(city_id)))
                conn.commit()
                flash('City updated successfully.', 'success')
            except sqlite3.IntegrityError:
                flash('City name already exists.', 'warning')

        elif action == 'delete':
            city_id = sanitize_input(request.form.get('city_id'), max_length=10)

            if not city_id or not city_id.isdigit():
                flash('Invalid city ID.', 'danger')
                conn.close()
                return redirect(url_for('manage_cities'))

            used = conn.execute('''
                SELECT COUNT(*) as count FROM trips
                WHERE from_city_id = ? OR to_city_id = ?
            ''', (int(city_id), int(city_id))).fetchone()['count']

            if used > 0:
                flash('Cannot delete city that is used in trips.', 'warning')
            else:
                conn.execute('DELETE FROM cities WHERE id = ?', (int(city_id),))
                conn.commit()
                flash('City deleted successfully.', 'success')

    cities = conn.execute('SELECT * FROM cities ORDER BY name').fetchall()
    conn.close()
    return render_template('manage_cities.html', cities=cities)

@app.route('/admin/buses', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_buses():
    conn = get_db()

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            conn.close()
            return redirect(url_for('manage_buses'))

        action = sanitize_input(request.form.get('action'))

        if action == 'add':
            bus_name = sanitize_input(request.form.get('bus_name'), max_length=100)
            bus_type = sanitize_input(request.form.get('bus_type'), max_length=50)
            total_seats_str = sanitize_input(request.form.get('total_seats'), max_length=4)

            if not bus_name or len(bus_name) < 2:
                flash('Bus name must be at least 2 characters.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            if bus_type not in ['Economy', 'Deluxe', 'VIP']:
                flash('Invalid bus type.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            if not total_seats_str or not total_seats_str.isdigit():
                flash('Invalid total seats.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            total_seats = int(total_seats_str)
            if total_seats < 1 or total_seats > 100:
                flash('Total seats must be between 1 and 100.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            conn.execute('''
                INSERT INTO buses (bus_name, bus_type, total_seats)
                VALUES (?, ?, ?)
            ''', (bus_name, bus_type, total_seats))
            conn.commit()
            flash('Bus added successfully.', 'success')

        elif action == 'edit':
            bus_id = sanitize_input(request.form.get('bus_id'), max_length=10)
            bus_name = sanitize_input(request.form.get('bus_name'), max_length=100)
            bus_type = sanitize_input(request.form.get('bus_type'), max_length=50)
            total_seats_str = sanitize_input(request.form.get('total_seats'), max_length=4)

            if not bus_id or not bus_id.isdigit():
                flash('Invalid bus ID.', 'danger')
                conn.close()
                return redirect(url_for('manage_buses'))

            if not bus_name or len(bus_name) < 2:
                flash('Bus name must be at least 2 characters.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            if bus_type not in ['Economy', 'Deluxe', 'VIP']:
                flash('Invalid bus type.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            if not total_seats_str or not total_seats_str.isdigit():
                flash('Invalid total seats.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            total_seats = int(total_seats_str)
            if total_seats < 1 or total_seats > 100:
                flash('Total seats must be between 1 and 100.', 'warning')
                conn.close()
                return redirect(url_for('manage_buses'))

            conn.execute('''
                UPDATE buses SET bus_name = ?, bus_type = ?, total_seats = ? WHERE id = ?
            ''', (bus_name, bus_type, total_seats, int(bus_id)))
            conn.commit()
            flash('Bus updated successfully.', 'success')

        elif action == 'delete':
            bus_id = sanitize_input(request.form.get('bus_id'), max_length=10)

            if not bus_id or not bus_id.isdigit():
                flash('Invalid bus ID.', 'danger')
                conn.close()
                return redirect(url_for('manage_buses'))

            used = conn.execute(
                'SELECT COUNT(*) as count FROM trips WHERE bus_id = ?', (int(bus_id),)
            ).fetchone()['count']

            if used > 0:
                flash('Cannot delete bus that is used in trips.', 'warning')
            else:
                conn.execute('DELETE FROM buses WHERE id = ?', (int(bus_id),))
                conn.commit()
                flash('Bus deleted successfully.', 'success')

    buses = conn.execute('SELECT * FROM buses ORDER BY id').fetchall()
    conn.close()
    return render_template('manage_buses.html', buses=buses)

@app.route('/admin/trips', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_trips():
    conn = get_db()

    if request.method == 'POST':
        if WTF_CSRF_ENABLED and not validate_csrf(request.form.get('csrf_token')):
            flash('Invalid request. Please try again.', 'danger')
            conn.close()
            return redirect(url_for('manage_trips'))

        action = sanitize_input(request.form.get('action'))

        if action == 'add':
            from_city_id = sanitize_input(request.form.get('from_city_id'), max_length=10)
            to_city_id = sanitize_input(request.form.get('to_city_id'), max_length=10)
            bus_id = sanitize_input(request.form.get('bus_id'), max_length=10)
            travel_date = sanitize_input(request.form.get('travel_date'), max_length=10)
            departure_time = sanitize_input(request.form.get('departure_time'), max_length=5)
            arrival_time = sanitize_input(request.form.get('arrival_time'), max_length=5)
            price_str = sanitize_input(request.form.get('price'), max_length=10)

            if not all([from_city_id, to_city_id, bus_id, travel_date, departure_time, arrival_time, price_str]):
                flash('Please fill in all fields.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            if not all(x.isdigit() for x in [from_city_id, to_city_id, bus_id]):
                flash('Invalid ID values.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            if from_city_id == to_city_id:
                flash('Origin and destination cities cannot be the same.', 'warning')
                conn.close()
                return redirect(url_for('manage_trips'))

            try:
                datetime.strptime(travel_date, '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            time_pattern = re.compile(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$')
            if not time_pattern.match(departure_time) or not time_pattern.match(arrival_time):
                flash('Invalid time format.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            try:
                price = float(price_str)
                if price <= 0 or price > 10000:
                    flash('Invalid price.', 'danger')
                    conn.close()
                    return redirect(url_for('manage_trips'))
            except ValueError:
                flash('Invalid price format.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            bus = conn.execute('SELECT total_seats FROM buses WHERE id = ?', (int(bus_id),)).fetchone()

            if not bus:
                flash('Bus not found.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            conn.execute('''
                INSERT INTO trips
                (from_city_id, to_city_id, bus_id, travel_date, departure_time, arrival_time, price, available_seats)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (int(from_city_id), int(to_city_id), int(bus_id), travel_date, departure_time, arrival_time, price, bus['total_seats']))
            conn.commit()
            flash('Trip added successfully.', 'success')

        elif action == 'edit':
            trip_id = sanitize_input(request.form.get('trip_id'), max_length=10)
            from_city_id = sanitize_input(request.form.get('from_city_id'), max_length=10)
            to_city_id = sanitize_input(request.form.get('to_city_id'), max_length=10)
            bus_id = sanitize_input(request.form.get('bus_id'), max_length=10)
            travel_date = sanitize_input(request.form.get('travel_date'), max_length=10)
            departure_time = sanitize_input(request.form.get('departure_time'), max_length=5)
            arrival_time = sanitize_input(request.form.get('arrival_time'), max_length=5)
            price_str = sanitize_input(request.form.get('price'), max_length=10)

            if not trip_id or not trip_id.isdigit():
                flash('Invalid trip ID.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            if not all([from_city_id, to_city_id, bus_id, travel_date, departure_time, arrival_time, price_str]):
                flash('Please fill in all fields.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            try:
                price = float(price_str)
                if price <= 0 or price > 10000:
                    flash('Invalid price.', 'danger')
                    conn.close()
                    return redirect(url_for('manage_trips'))
            except ValueError:
                flash('Invalid price format.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            conn.execute('''
                UPDATE trips
                SET from_city_id = ?, to_city_id = ?, bus_id = ?,
                    travel_date = ?, departure_time = ?, arrival_time = ?, price = ?
                WHERE id = ?
            ''', (int(from_city_id), int(to_city_id), int(bus_id), travel_date, departure_time, arrival_time, price, int(trip_id)))
            conn.commit()
            flash('Trip updated successfully.', 'success')

        elif action == 'delete':
            trip_id = sanitize_input(request.form.get('trip_id'), max_length=10)

            if not trip_id or not trip_id.isdigit():
                flash('Invalid trip ID.', 'danger')
                conn.close()
                return redirect(url_for('manage_trips'))

            conn.execute('DELETE FROM trips WHERE id = ?', (int(trip_id),))
            conn.commit()
            flash('Trip deleted successfully.', 'success')

    trips = conn.execute('''
        SELECT
            trips.id,
            trips.travel_date,
            trips.departure_time,
            trips.arrival_time,
            trips.price,
            trips.available_seats,
            c1.name as from_city,
            c2.name as to_city,
            buses.bus_name,
            buses.bus_type
        FROM trips
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        ORDER BY trips.travel_date DESC, trips.departure_time
    ''').fetchall()

    cities = conn.execute('SELECT * FROM cities ORDER BY name').fetchall()
    buses = conn.execute('SELECT * FROM buses ORDER BY bus_name').fetchall()
    conn.close()

    return render_template('manage_trips.html', trips=trips, cities=cities, buses=buses)

@app.route('/admin/bookings')
@login_required
@role_required('admin')
def all_bookings():
    conn = get_db()
    bookings = conn.execute('''
        SELECT
            bookings.*,
            users.full_name as customer_name,
            users.email as customer_email,
            c1.name as from_city,
            c2.name as to_city,
            trips.travel_date,
            trips.departure_time,
            buses.bus_name,
            buses.bus_type,
            payment_methods.name as payment_method,
            payments.payment_date
        FROM bookings
        JOIN users ON bookings.user_id = users.id
        JOIN trips ON bookings.trip_id = trips.id
        JOIN cities c1 ON trips.from_city_id = c1.id
        JOIN cities c2 ON trips.to_city_id = c2.id
        JOIN buses ON trips.bus_id = buses.id
        LEFT JOIN payments ON bookings.payment_id = payments.id
        LEFT JOIN payment_methods ON payments.method_id = payment_methods.id
        ORDER BY bookings.booking_date DESC, bookings.id DESC
    ''').fetchall()
    conn.close()

    return render_template('all_bookings.html', bookings=bookings)

@app.route('/admin/customers')
@login_required
@role_required('admin')
def customers():
    conn = get_db()
    customers_list = conn.execute('''
        SELECT * FROM users WHERE role = 'customer' ORDER BY full_name
    ''').fetchall()
    conn.close()

    return render_template('customers.html', customers=customers_list)

def validate_csrf(token):
    if 'csrf_token' not in session:
        return False
    return session['csrf_token'] == token

if __name__ == '__main__':
    print("=" * 50)
    print("Bus Ticket Booking System")
    print("=" * 50)
    print("Open your browser and go to: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True)