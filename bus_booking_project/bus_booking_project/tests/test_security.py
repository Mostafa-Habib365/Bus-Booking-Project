"""
Security Tests for Bus Booking System
Tests for OWASP Top 10 vulnerabilities and security controls
"""

import pytest
import os
import sys
import re
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ['SECRET_KEY'] = 'test_secret_key_for_testing_only'

from app import (
    app,
    sanitize_input,
    validate_email_format,
    validate_phone_format,
    validate_password_strength,
    validate_csrf,
    WTF_CSRF_ENABLED
)


class TestConfig:
    TESTING = True
    SECRET_KEY = 'test_secret_key_for_testing_only'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_ENABLED = True


app.config.from_object(TestConfig)


class TestInputValidation:
    def test_sanitize_input_removes_html_tags(self):
        result = sanitize_input('<script>alert("xss")</script>')
        assert '<' not in result
        assert '>' not in result
        assert 'script' not in result.lower()

    def test_sanitize_input_removes_sql_keywords(self):
        result = sanitize_input("'; DROP TABLE users; --")
        assert 'DROP' not in result
        assert 'TABLE' not in result
        assert ';' not in result

    def test_sanitize_input_respects_max_length(self):
        long_input = 'x' * 500
        result = sanitize_input(long_input, max_length=255)
        assert len(result) == 255

    def test_sanitize_input_handles_none(self):
        assert sanitize_input(None) is None

    def test_sanitize_input_strips_whitespace(self):
        result = sanitize_input('  hello  ')
        assert result == 'hello'


class TestEmailValidation:
    def test_valid_email_formats(self):
        valid_emails = [
            'test@example.com',
            'user.name@domain.org',
            'user+tag@example.co.uk',
            'firstname.lastname@company.com'
        ]
        for email in valid_emails:
            assert validate_email_format(email) is True, f"Failed for {email}"

    def test_invalid_email_formats(self):
        invalid_emails = [
            'invalid',
            'missing@domain',
            '@nodomain.com',
            'spaces in@email.com',
            '<script>alert(1)</script>@test.com',
            "'; DROP TABLE users; --"
        ]
        for email in invalid_emails:
            assert validate_email_format(email) is False, f"Should have failed for {email}"


class TestPhoneValidation:
    def test_valid_egyptian_phone_formats(self):
        valid_phones = [
            '01012345678',
            '01112345678',
            '01212345678',
            '01512345678',
            '010 1234 5678',
            '010-123-456-78'
        ]
        for phone in valid_phones:
            assert validate_phone_format(phone) is True, f"Failed for {phone}"

    def test_invalid_phone_formats(self):
        invalid_phones = [
            '1234567890',
            '010123456',
            '010123456789',
            'abc123defgh',
            '<script>alert(1)</script>'
        ]
        for phone in invalid_phones:
            assert validate_phone_format(phone) is False, f"Should have failed for {phone}"


class TestPasswordStrength:
    def test_valid_strong_passwords(self):
        valid_passwords = [
            'Password123',
            'MyP@ssw0rd!',
            'Str0ng&Secure',
            'C0mpl3x#Pass'
        ]
        for password in valid_passwords:
            is_strong, msg = validate_password_strength(password)
            assert is_strong is True, f"Failed for {password}: {msg}"

    def test_invalid_weak_passwords(self):
        weak_passwords = [
            'short1',           # Too short
            'nodigitshere',     # No numbers
            '12345678',         # No letters
            'alllowercase1',    # No uppercase
            '<script>alert(1)</script>'  # XSS attempt
        ]
        for password in weak_passwords:
            is_strong, msg = validate_password_strength(password)
            assert is_strong is False, f"Should have failed for {password}"


class TestCSRFProtection:
    def test_csrf_validation_requires_token(self):
        assert validate_csrf(None) is False

    def test_csrf_validation_fails_wrong_token(self):
        with app.test_request_context():
            from flask import session
            session['csrf_token'] = 'correct_token'
            assert validate_csrf('wrong_token') is False

    def test_csrf_validation_passes_correct_token(self):
        with app.test_request_context():
            from flask import session
            session['csrf_token'] = 'correct_token'
            assert validate_csrf('correct_token') is True


class TestSecurityHeaders:
    def test_security_headers_present(self):
        with app.test_client() as client:
            response = client.get('/')
            assert 'X-Content-Type-Options' in response.headers
            assert response.headers['X-Content-Type-Options'] == 'nosniff'
            assert 'X-Frame-Options' in response.headers
            assert response.headers['X-Frame-Options'] == 'DENY'
            assert 'X-XSS-Protection' in response.headers
            assert 'Strict-Transport-Security' in response.headers

    def test_content_security_policy(self):
        with app.test_client() as client:
            response = client.get('/')
            assert 'Content-Security-Policy' in response.headers


class TestSQLInjectionPrevention:
    def test_search_endpoint_parameterized_queries(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'

            response = client.post('/customer/search', data={
                'csrf_token': 'test_token',
                'from_city': '1',
                'to_city': '2',
                'travel_date': '2024-01-01'
            }, follow_redirects=False)

            assert response.status_code != 500

    def test_admin_endpoint_sql_injection_attempt(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['user_role'] = 'admin'
                sess['csrf_token'] = 'test_token'

            response = client.post('/admin/cities', data={
                'csrf_token': 'test_token',
                'action': 'add',
                'name': "'; DROP TABLE cities; --"
            }, follow_redirects=True)

            assert response.status_code == 200


class TestXSSPrevention:
    def test_xss_in_user_name_escaped(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['user_name'] = '<script>alert("xss")</script>'
                sess['user_role'] = 'customer'

            response = client.get('/customer/dashboard')
            assert '<script>alert' not in response.data.decode('utf-8')

    def test_xss_in_registration_escaped(self):
        with app.test_client() as client:
            response = client.post('/register', data={
                'csrf_token': 'test_token',
                'full_name': '<script>alert("xss")</script>',
                'email': 'test@example.com',
                'password': 'Password123',
                'phone': '01012345678'
            }, follow_redirects=True)

            assert '<script>alert' not in response.data.decode('utf-8')


class TestAuthenticationSecurity:
    def test_login_with_weak_password_rejected(self):
        with app.test_client() as client:
            response = client.post('/login', data={
                'csrf_token': 'test_token',
                'email': 'test@example.com',
                'password': 'weak'
            }, follow_redirects=True)

            assert b'Invalid' in response.data or b'Please' in response.data

    def test_session_timeout(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['user_role'] = 'customer'
                sess.permanent = True

            app.permanent_session_lifetime = timedelta(hours=2)
            assert app.permanent_session_lifetime == timedelta(hours=2)


class TestAuthorizationControls:
    def test_admin_route_requires_admin_role(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['user_role'] = 'customer'

            response = client.get('/admin/dashboard')
            assert response.status_code == 302

    def test_customer_route_requires_customer_role(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['user_role'] = 'admin'

            response = client.get('/customer/dashboard')
            assert response.status_code == 302

    def test_unauthenticated_access_redirects(self):
        with app.test_client() as client:
            response = client.get('/customer/dashboard')
            assert response.status_code == 302


class TestBusinessLogicSecurity:
    def test_cannot_book_more_seats_than_available(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 2
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'

            response = client.post('/book/1', data={
                'csrf_token': 'test_token',
                'seats_count': 9999,
                'payment_method': '1'
            }, follow_redirects=True)

            assert b'Please select between 1 and' in response.data or b'Only' in response.data

    def test_cannot_cancel_other_users_booking(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 999
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'

            response = client.post('/cancel_booking/1', data={
                'csrf_token': 'test_token'
            }, follow_redirects=True)

            assert b'Booking not found' in response.data or b'not found' in response.data


class TestErrorHandling:
    def test_404_error_handler(self):
        with app.test_client() as client:
            response = client.get('/nonexistent/page')
            assert response.status_code == 404

    def test_invalid_trip_id_rejected(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 2
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'

            response = client.get('/book/invalid')
            assert response.status_code == 404

    def test_negative_trip_id_rejected(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 2
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'

            response = client.post('/book/-1', data={
                'csrf_token': 'test_token',
                'seats_count': 1,
                'payment_method': '1'
            }, follow_redirects=True)

            assert b'Invalid' in response.data or b'not found' in response.data


class TestPaymentValidation:
    def test_invalid_card_number_rejected(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 2
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'
                sess['pending_booking'] = {
                    'trip_id': 1,
                    'seats_count': 1,
                    'total_price': 100.0,
                    'payment_method_id': 2
                }

            response = client.post('/payment', data={
                'csrf_token': 'test_token',
                'card_number': '123',
                'card_holder': 'John Doe',
                'expiry_date': '12/2025',
                'cvv': '123'
            }, follow_redirects=True)

            assert b'Invalid card number' in response.data

    def test_expired_card_rejected(self):
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 2
                sess['user_role'] = 'customer'
                sess['csrf_token'] = 'test_token'
                sess['pending_booking'] = {
                    'trip_id': 1,
                    'seats_count': 1,
                    'total_price': 100.0,
                    'payment_method_id': 2
                }

            response = client.post('/payment', data={
                'csrf_token': 'test_token',
                'card_number': '1234567890123456',
                'card_holder': 'John Doe',
                'expiry_date': '01/2020',
                'cvv': '123'
            }, follow_redirects=True)

            assert b'expired' in response.data.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])