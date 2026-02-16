from flask import Flask, request,render_template,jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from chatApp.models import db, User, Message
from datetime import datetime

# ------------------------------
# App Configuration
# ------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key"
app.config["JWT_SECRET_KEY"] = "jwt-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Create tables
with app.app_context():
    db.create_all()

# ------------------------------
# Authentication Routes
# ------------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=username)
    return jsonify({"access_token": token}), 200

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello {current_user}, access granted"}), 200

# ------------------------------
# Chat Routes
# ------------------------------
@app.route("/chat", methods=["POST"])
@jwt_required()
def send_message():
    current_user = get_jwt_identity()
    data = request.json
    message_text = data.get("message")

    if not message_text:
        return jsonify({"error": "Message cannot be empty"}), 400

    message = Message(username=current_user, message=message_text)
    db.session.add(message)
    db.session.commit()

    return jsonify({"message": "Message sent successfully"}), 201

@app.route("/chat", methods=["GET"])
@jwt_required()
def get_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    result = [
        {
            "username": msg.username,
            "message": msg.message,
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for msg in messages
    ]
    return jsonify(result), 200

@app.route("/")
def home():
    return render_template("index.html")

# ------------------------------
# Run Server
# ------------------------------
if __name__ == "__main__":
    app.run(debug=True)
