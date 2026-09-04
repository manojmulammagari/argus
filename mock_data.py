"""
File: mock_data.py
Stores hardcoded mock payloads for demo mode to keep the main router clean.
"""

DEMO_DIFF = """\
diff --git a/auth/login.py b/auth/login.py
+++ b/auth/login.py
@@ -0,0 +1,32 @@
+import hashlib, logging, jwt, psycopg2
+
+AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
+STRIPE_SK = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
+DB_PASS = "super_secret_prod_2024"
+
+def get_patient(patient_id):
+    p = db.query(patient_id)
+    logging.info(f"Patient: SSN={p.ssn}, DOB={p.dob}, Diagnosis={p.diagnosis}")
+    return p
+
+def search_users(name):
+    sql = "SELECT * FROM users WHERE name = '" + name + "'"
+    cursor.execute(sql)
+    return cursor.fetchall()
+
+def hash_password(pwd):
+    return hashlib.md5(pwd.encode()).hexdigest()
+
+def verify_token(token):
+    return jwt.decode(token, algorithms=["HS256", "none"],
+                      options={"verify_signature": False})
+
+def render_welcome(req):
+    name = req.args.get("username", "guest")
+    return f"<h1>Welcome {name}!</h1>"
"""