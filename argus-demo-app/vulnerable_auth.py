"""
ARGUS Demo Vulnerable App
INTENTIONALLY VULNERABLE CODE FOR DEMONSTRATIONS ONLY
"""
import hashlib
import os
import logging
import jwt

AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
DB_PASSWORD    = "admin123"
logger = logging.getLogger(__name__)

def get_patient(patient_id: str):
    """CWE-532: PHI logged to stdout — HIPAA §164.312(b) violation"""
    patient = {"ssn": "123-45-6789", "dob": "1990-01-01", "name": "John Doe"}
    logger.info(f"Retrieved patient SSN: {patient['ssn']}, DOB: {patient['dob']}")
    return patient

def search_users(name: str):
    """CWE-89: SQL Injection"""
    import psycopg2
    conn = psycopg2.connect(os.environ.get("DATABASE_URL", ""))
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()

def hash_password(pwd: str) -> str:
    """CWE-327: Weak cryptography — MD5 is broken"""
    return hashlib.md5(pwd.encode()).hexdigest()

def verify_token(token: str):
    """CWE-287: JWT algorithm confusion allows authentication bypass"""
    return jwt.decode(
        token,
        algorithms=["HS256", "none"],
        options={"verify_signature": False}
    )

def render_profile(request_args: dict) -> str:
    """CWE-79: Reflected XSS"""
    name = request_args.get("name", "")
    return f"<h1>Hello {name}</h1>"
