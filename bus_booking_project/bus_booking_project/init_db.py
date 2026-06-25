"""
Database initialization script for Bus Ticket Booking System
Run this first to create the database and add sample data
"""

import sqlite3
from werkzeug.security import generate_password_hash
import os

# Remove old database if exists to start fresh
if os.path.exists('database.db'):
    os.remove('database.db')
    print("Old database removed.")

# Connect to SQLite database (creates file if not exists)
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# ============================
# Create tables
# ============================

# Users table (customers + admin)
cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT,
        role TEXT DEFAULT 'customer'  -- 'admin' or 'customer'
    )
''')

# Cities table
cursor.execute('''
    CREATE TABLE cities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
''')

# Buses table
cursor.execute('''
    CREATE TABLE buses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_name TEXT NOT NULL,
        bus_type TEXT NOT NULL,  -- Economy, Deluxe, VIP
        total_seats INTEGER NOT NULL
    )
''')

# Trips table
cursor.execute('''
    CREATE TABLE trips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_city_id INTEGER NOT NULL,
        to_city_id INTEGER NOT NULL,
        bus_id INTEGER NOT NULL,
        travel_date TEXT NOT NULL,  -- YYYY-MM-DD
        departure_time TEXT NOT NULL,  -- HH:MM
        arrival_time TEXT NOT NULL,    -- HH:MM
        price REAL NOT NULL,
        available_seats INTEGER NOT NULL,
        FOREIGN KEY (from_city_id) REFERENCES cities(id),
        FOREIGN KEY (to_city_id) REFERENCES cities(id),
        FOREIGN KEY (bus_id) REFERENCES buses(id)
    )
''')

# Bookings table
cursor.execute('''
    CREATE TABLE bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        trip_id INTEGER NOT NULL,
        seats_count INTEGER NOT NULL,
        total_price REAL NOT NULL,
        booking_date TEXT NOT NULL,  -- YYYY-MM-DD
        status TEXT DEFAULT 'Confirmed',  -- 'Confirmed' or 'Cancelled'
        payment_id INTEGER,  -- FK to payments table
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (trip_id) REFERENCES trips(id)
    )
''')

# Payment methods table
cursor.execute('''
    CREATE TABLE payment_methods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        is_active INTEGER DEFAULT 1
    )
''')

# Payments table
cursor.execute('''
    CREATE TABLE payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        transaction_id TEXT,
        payment_date TEXT NOT NULL,  -- YYYY-MM-DD HH:MM:SS
        status TEXT DEFAULT 'Pending',  -- 'Pending', 'Completed', 'Failed', 'Refunded'
        FOREIGN KEY (method_id) REFERENCES payment_methods(id)
    )
''')

print("Tables created successfully.")

# ============================
# Insert sample data
# ============================

# --- Users ---
# Admin account
admin_password = generate_password_hash('admin123')
cursor.execute('''
    INSERT INTO users (full_name, email, password, phone, role)
    VALUES (?, ?, ?, ?, ?)
''', ('System Admin', 'admin@example.com', admin_password, '01000000000', 'admin'))

# Default customer account
customer_password = generate_password_hash('customer123')
cursor.execute('''
    INSERT INTO users (full_name, email, password, phone, role)
    VALUES (?, ?, ?, ?, ?)
''', ('Ahmed Hassan', 'customer@example.com', customer_password, '01012345678', 'customer'))

# Another sample customer
customer2_password = generate_password_hash('password456')
cursor.execute('''
    INSERT INTO users (full_name, email, password, phone, role)
    VALUES (?, ?, ?, ?, ?)
''', ('Sara Mohamed', 'sara@example.com', customer2_password, '01098765432', 'customer'))

# --- Egyptian Cities ---
cities = [
    'Cairo',
    'Alexandria',
    'Hurghada',
    'Sharm El Sheikh',
    'Dahab',
    'Luxor',
    'Aswan',
    'Mansoura',
    'Tanta',
    'Minya'
]

for city in cities:
    cursor.execute('INSERT INTO cities (name) VALUES (?)', (city,))

# --- Buses ---
buses = [
    ('Economy Bus A1', 'Economy', 50),
    ('Economy Bus A2', 'Economy', 50),
    ('Deluxe Bus B1', 'Deluxe', 35),
    ('Deluxe Bus B2', 'Deluxe', 35),
    ('VIP Bus C1', 'VIP', 20),
    ('VIP Bus C2', 'VIP', 20)
]

for bus in buses:
    cursor.execute('''
        INSERT INTO buses (bus_name, bus_type, total_seats)
        VALUES (?, ?, ?)
    ''', bus)

# --- Sample Trips ---
# Some trips for today and future dates
from datetime import datetime, timedelta

today = datetime.now().date()
tomorrow = today + timedelta(days=1)
day_after = today + timedelta(days=2)

trips = [
    # (from_city_id, to_city_id, bus_id, travel_date, departure_time, arrival_time, price, available_seats)
    (1, 2, 1, str(today), '06:00', '09:30', 120.0, 50),      # Cairo -> Alexandria, Economy
    (1, 2, 3, str(today), '08:00', '11:00', 200.0, 35),      # Cairo -> Alexandria, Deluxe
    (1, 2, 5, str(today), '10:00', '12:30', 350.0, 20),      # Cairo -> Alexandria, VIP
    (2, 1, 2, str(today), '14:00', '17:30', 120.0, 50),      # Alexandria -> Cairo, Economy
    (1, 3, 1, str(tomorrow), '22:00', '06:00', 250.0, 50),   # Cairo -> Hurghada, Economy (overnight)
    (1, 3, 5, str(tomorrow), '23:00', '06:30', 600.0, 20),   # Cairo -> Hurghada, VIP
    (3, 4, 3, str(tomorrow), '09:00', '12:00', 180.0, 35),  # Hurghada -> Sharm, Deluxe
    (1, 6, 2, str(day_after), '07:00', '15:00', 300.0, 50), # Cairo -> Luxor, Economy
    (1, 6, 4, str(day_after), '20:00', '05:00', 450.0, 35), # Cairo -> Luxor, Deluxe (overnight)
    (6, 7, 1, str(day_after), '08:00', '12:00', 150.0, 50),  # Luxor -> Aswan, Economy
    (8, 1, 2, str(today), '06:30', '09:00', 100.0, 50),      # Mansoura -> Cairo, Economy
    (9, 1, 1, str(tomorrow), '07:00', '09:30', 100.0, 50),   # Tanta -> Cairo, Economy
    (1, 10, 3, str(day_after), '08:00', '12:00', 180.0, 35), # Cairo -> Minya, Deluxe
    (4, 5, 5, str(tomorrow), '10:00', '12:30', 200.0, 20),   # Sharm -> Dahab, VIP
]

for trip in trips:
    cursor.execute('''
        INSERT INTO trips (from_city_id, to_city_id, bus_id, travel_date, departure_time, arrival_time, price, available_seats)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', trip)

# --- Sample Booking ---
# One confirmed booking for the default customer
cursor.execute('''
    INSERT INTO bookings (user_id, trip_id, seats_count, total_price, booking_date, status)
    VALUES (?, ?, ?, ?, ?, ?)
''', (2, 3, 2, 700.0, str(today), 'Confirmed'))

# Update available seats for that trip
cursor.execute('''
    UPDATE trips SET available_seats = available_seats - ? WHERE id = ?
''', (2, 3))

# --- Payment Methods ---
payment_methods = [
    ('Cash', 'Pay with cash upon arrival at the station'),
    ('Credit Card', 'Pay securely with your credit or debit card'),
    ('Fawry', 'Pay using Fawry e-wallet or Fawry kiosks'),
    ('Visa', 'Pay with Visa card (Credit/Debit)'),
    ('Wallet', 'Pay using your digital wallet')
]

for method in payment_methods:
    cursor.execute('''
        INSERT INTO payment_methods (name, description) VALUES (?, ?)
    ''', method)

# --- Sample Payment for existing booking ---
cursor.execute('''
    INSERT INTO payments (method_id, amount, transaction_id, payment_date, status)
    VALUES (?, ?, ?, ?, ?)
''', (1, 700.0, 'CASH-' + str(today) + '-001', str(today) + ' 10:30:00', 'Completed'))

# Update the existing booking with payment reference
cursor.execute('''
    UPDATE bookings SET payment_id = 1 WHERE id = 1
''')

# Commit and close
conn.commit()
conn.close()

print("Sample data inserted successfully.")
print("\n--- Default Login Credentials ---")
print("Admin:    admin@example.com / admin123")
print("Customer: customer@example.com / customer123")
print("Customer: sara@example.com / password456")
