import hmac
import hashlib
import json

# Your auth secret from deadlight.conf
secret = "your_auth_secret_here"

# Request body
body = json.dumps({
    "from": "gnarzilla@deadlight.boo",
    "to": "dealight.boo@gmail.com", 
    "subject": "Authenticated Test",
    "body": "This email requires HMAC authentication"
})

# Generate HMAC
signature = hmac.new(
    secret.encode('utf-8'),
    body.encode('utf-8'),
    hashlib.sha256
).hexdigest()

print(f"Authorization: Bearer {signature}")
print(f"\nBody: {body}")
