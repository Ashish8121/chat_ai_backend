from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text  # ✅ FIXED: Import `text` to avoid NameError
from pydantic import BaseModel, EmailStr
import bcrypt
import uvicorn
from contextlib import asynccontextmanager
from database_models import User, db_engine, SessionLocal, Base, Messages
from jwt_token import generate_jwt , verify_jwt  # Your JWT helper
from fastapi import Query
app = FastAPI()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ✅ This runs once when the app starts
    Base.metadata.create_all(bind=db_engine)
    yield
    # 🔒 You can also close DB connections or cleanup here if needed

app = FastAPI(lifespan=lifespan)

# ✅ CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Database Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# ✅ Login Schema
class LoginRequest(BaseModel):
    email: str
    password: str

@app.get("/")
def read_root():
    return {"message": "Backend is up and running"}





# ✅ /check_user route
@app.post("/check_user")
def check_user(request: LoginRequest, db: Session = Depends(get_db)):
    if not request.email or not request.password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    user = db.query(User).filter_by(email=request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email doesn't exist")

    if not bcrypt.checkpw(request.password.encode('utf-8'), user.password.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Password incorrect")

    token = generate_jwt(user.id)
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "token": token
    }

# ✅ Register Schema
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

# ✅ /add_user route
@app.post("/add_user")
def add_user(request: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=request.email).first():
        raise HTTPException(status_code=409, detail="Email already exists")

    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(
        name=request.name,
        email=request.email,
        password=hashed_password.decode('utf-8')
    )
    db.add(new_user)
    db.commit()


    return {"message": "User added successfully"}

@app.get("/search_users")
def search_users(search: str = Query(default="", description="Search by user name"), db: Session = Depends(get_db)):
    if search == "":
        return []

    users = db.query(User).filter(User.name.ilike(f"%{search}%")).all()
    return [{"id": user.id, "name": user.name} for user in users]



# ✅ SendMessage Schema
class SendMessageRequest(BaseModel):
    recipient_id: int
    message: str

# ✅ /send_message route
@app.post("/send_message")
def send_message(
    request: Request,
    body: SendMessageRequest,
    db: Session = Depends(get_db)
):
    # Extract and verify JWT
    auth_header = request.headers.get("Authorization")
    current_user_id = verify_jwt(auth_header)
    if current_user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not body.recipient_id or not body.message:
        raise HTTPException(status_code=400, detail="Recipient and message required")

    user_message = Messages(
        sender_id=current_user_id,
        recipient_id=body.recipient_id,
        text=body.message
    )
    db.add(user_message)
    db.commit()
    db.refresh(user_message)

    return {"data": user_message.to_dict()}




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# ✅ /get_messages_with_user
@app.get("/get_messages_with_user/{recipient_id}")
def get_messages_with_user(
    recipient_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    # Verify JWT
    auth_header = request.headers.get("Authorization")
    current_user_id = verify_jwt(auth_header)
    if current_user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Fetch messages between current_user and recipient
    messages = db.query(Messages).filter(
        ((Messages.sender_id == current_user_id) & (Messages.recipient_id == recipient_id)) |
        ((Messages.sender_id == recipient_id) & (Messages.recipient_id == current_user_id))
    ).order_by(Messages.timestamp).all()

    return {"messages": [m.to_dict() for m in messages]}


# ✅ /get_active_chats
@app.get("/get_active_chats")
def get_active_chats(
    request: Request,
    db: Session = Depends(get_db)
):
    # Verify JWT
    auth_header = request.headers.get("Authorization")
    current_user_id = verify_jwt(auth_header)
    if current_user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Return all users except current user
    users = db.query(User).filter(User.id != current_user_id).all()
    user_list = [{"id": user.id, "name": user.name} for user in users]

    return {"users": user_list}

# ✅ Run the app with Uvicorn
if __name__ == "__main__":
    import os
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)


















































































# from flask import Flask, request, jsonify
# from flask_cors import CORS
# from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy import or_
# from jwt_token import generate_jwt, verify_jwt
# import bcrypt
# from database_models import User, Messages, db
# from datetime import datetime

# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Fin%40885500@localhost/testdb'
# CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)
# db.init_app(app)

# @app.route('/add_user', methods=['POST'])
# def add_user():
#     data = request.get_json()
#     name = data.get('name')
#     email = data.get('email')
#     password = data.get('password')

#     if User.query.filter_by(name=name).first():
#         return jsonify({'message': 'Name already exists'}), 409
#     if User.query.filter_by(email=email).first():
#         return jsonify({'message': 'Email already exists'}), 409

#     hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
#     new_user = User(name=name, email=email, password=hashed_password.decode('utf-8'))
#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({'message': 'User added successfully'}), 201

# @app.route('/check_user', methods=['POST'])
# def check_user():
#     data = request.get_json()
#     email = data.get('email')
#     password = data.get('password')

#     user = User.query.filter_by(email=email).first()
#     if not user:
#         return jsonify({'error': "Email doesn't exist"}), 200
#     if email == '' or password == '':
#         return jsonify({'error': "Email and password are required"}), 200
#     if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
#         return jsonify({'error': 'Password incorrect'}), 200

#     token = generate_jwt(user.id)
#     return jsonify({'id': user.id, 'name': user.name, 'email': user.email, 'token': token}), 200

# @app.route('/ai_reply', methods=['POST'])
# def ai_reply():
#     auth_header = request.headers.get('Authorization')
#     current_user_id = verify_jwt(auth_header)
#     if current_user_id is None:
#         return jsonify({'error': 'Unauthorized'}), 401

#     data = request.get_json()
#     recipient_id = data.get('recipient_id')
#     if not recipient_id:
#         return jsonify({'error': 'Missing recipient_id'}), 400

#     # ✅ Fetch full conversation context ordered by timestamp
#     messages = Messages.query.filter(
#         ((Messages.sender_id == current_user_id) & (Messages.recipient_id == recipient_id)) |
#         ((Messages.sender_id == recipient_id) & (Messages.recipient_id == current_user_id))
#     ).order_by(Messages.timestamp).all()

#     if not messages:
#         return jsonify({'message': 'No conversation history found'}), 200

#     # ✅ Build chat_history list for Colab endpoint
#     chat_history = []
#     for msg in messages:
#         sender_label = "You" if msg.sender_id == current_user_id else "User"
#         chat_history.append(f"{sender_label}: {msg.text}")

#     # ✅ Identify last user message needing AI reply
#     last_user_message = next(
#         (m for m in reversed(messages)
#          if m.sender_id == recipient_id and not m.is_ai_replied),
#         None
#     )

#     if not last_user_message:
#         return jsonify({'message': 'No new user message to reply'}), 200

#     # ✅ Call Google Colab AI via ngrok tunnel with chat_history
#     import requests
#     COLAB_NGROK_URL = "https://2040576ea838.ngrok-free.app"

#     payload = {
#         "chat_history": chat_history
#     }

#     try:
#         colab_response = requests.post(
#             f"{COLAB_NGROK_URL}/ai_reply",
#             json=payload,
#             timeout=30
#         )

#         if colab_response.status_code == 200:
#             colab_data = colab_response.json()
#             answer = colab_data.get('reply') or "Sorry, AI returned no reply."
#         else:
#             print("Colab AI error:", colab_response.text)
#             answer = "Sorry, AI service failed."

#     except Exception as e:
#         print("Error calling Colab AI:", e)
#         answer = "Sorry, AI service is unavailable right now."

#     # ✅ Save AI reply as current_user to recipient
#     ai_reply_message = Messages(
#         sender_id=current_user_id,
#         recipient_id=recipient_id,
#         text=answer,
#         is_ai=True
#     )
#     db.session.add(ai_reply_message)

#     # ✅ Mark user message as replied
#     last_user_message.is_ai_replied = True

#     db.session.commit()

#     return jsonify({'ai_reply': ai_reply_message.to_dict()}), 200




# @app.route('/send_message', methods=['POST'])
# def send_message():
#     auth_header = request.headers.get('Authorization')
#     current_user_id = verify_jwt(auth_header)
#     if current_user_id is None:
#         return jsonify({'error': 'Unauthorized'}), 401

#     data = request.get_json()
#     recipient_id = data.get('recipient_id')
#     message_text = data.get('message')

#     if not recipient_id or not message_text:
#         return jsonify({'error': 'Recipient and message required'}), 400

#     user_message = Messages(
#         sender_id=current_user_id,
#         recipient_id=recipient_id,
#         text=message_text
#     )
#     db.session.add(user_message)
#     db.session.commit()

#     return jsonify({'data': user_message.to_dict()}), 200

# # ✅ Other routes remain unchanged, no logic edits needed here

# @app.route('/delete_chat/<int:user_id>', methods=['DELETE', 'OPTIONS'])
# def delete_chat(user_id):
#     if request.method == 'OPTIONS':
#         return '', 200

#     auth_header = request.headers.get('Authorization')
#     current_user_id = verify_jwt(auth_header)
#     if current_user_id is None:
#         return jsonify({'error': 'Unauthorized'}), 401

#     Messages.query.filter(
#         ((Messages.sender_id == current_user_id) & (Messages.recipient_id == user_id)) |
#         ((Messages.sender_id == user_id) & (Messages.recipient_id == current_user_id))
#     ).delete()

#     db.session.commit()
#     return jsonify({'message': 'Chat deleted successfully'}), 200

# @app.route('/search_users', methods=['GET'])
# def search_users():
#     search_query = request.args.get('search', '')
#     if search_query == '':
#         return jsonify([]), 200

#     users = User.query.filter(User.name.ilike(f"%{search_query}%")).all()
#     return jsonify([{'id': user.id, 'name': user.name} for user in users]), 200


# @app.route('/get_messages_with_user/<int:recipient_id>', methods=['GET'])
# def get_messages_with_user(recipient_id):
#     auth_header = request.headers.get('Authorization')
#     current_user_id = verify_jwt(auth_header)
#     if current_user_id is None:
#         return jsonify({'error': 'Unauthorized'}), 401

#     messages = Messages.query.filter(
#         ((Messages.sender_id == current_user_id) & (Messages.recipient_id == recipient_id)) |
#         ((Messages.sender_id == recipient_id) & (Messages.recipient_id == current_user_id))
#     ).order_by(Messages.timestamp).all()

#     return jsonify({'messages': [m.to_dict() for m in messages]}), 200

# @app.route('/get_active_chats', methods=['GET'])
# def get_active_chats():
#     auth_header = request.headers.get('Authorization')
#     current_user_id = verify_jwt(auth_header)
#     if current_user_id is None:
#         return jsonify({'error': 'Unauthorized'}), 401

#     # Return all users except the current user
#     users = User.query.filter(User.id != current_user_id).all()
#     user_list = [{'id': user.id, 'name': user.name} for user in users]

#     return jsonify({'users': user_list}), 200


# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)
