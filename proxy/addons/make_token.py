"""Issue a signed company token:  python make_token.py alice@corp.local"""
import hashlib
import hmac
import os
import sys

secret = os.environ["DLP_TOKEN_SECRET"].encode()
email = sys.argv[1]
signature = hmac.new(secret, email.encode(), hashlib.sha256).hexdigest()
print(f"{email}:{signature}")