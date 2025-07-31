import jwt
from datetime import datetime,timezone, timedelta 

SECRET_KEY = '8146233624'

def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours= 24)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token 


def verify_jwt(auth_header):
    if not auth_header or not auth_header.startswith('Bearer'):
        return None
    parts = auth_header.split(' ')
    if len(parts) != 2:
        return None
    token = parts[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = decoded['user_id']
        return user_id
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None



