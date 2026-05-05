from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from utils.db import db, User

login_manager = LoginManager()
login_manager.login_view = "/login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def register_user(username, email, password):
    if User.query.filter_by(email=email.strip().lower()).first():
        return False, "Email already registered"
    if User.query.filter_by(username=username.strip()).first():
        return False, "Username already taken"
    user = User(
        username=username.strip(),
        email=email.strip().lower(),
        password_hash=generate_password_hash(password),
        role="player", score=0,
    )
    db.session.add(user)
    db.session.commit()
    return True, user

def authenticate_user(email, password):
    user = User.query.filter_by(email=email.strip().lower()).first()
    if user and check_password_hash(user.password_hash, password):
        return True, user
    return False, "Invalid email or password"

def seed_admin(app):
    with app.app_context():
        if not User.query.filter_by(role="admin").first():
            admin = User(
                username="admin",
                email="admin@ctf.local",
                password_hash=generate_password_hash("Admin@1234"),
                role="admin", score=0,
            )
            db.session.add(admin)
            db.session.commit()
            print("[CTF] Admin created: admin@ctf.local / Admin@1234")
        else:
            print("[CTF] Admin already exists")
