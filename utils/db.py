from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(50),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(10),  default="player")
    score         = db.Column(db.Integer,     default=0)
    bio           = db.Column(db.Text,        default="")
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)
    submissions   = db.relationship("Submission", backref="user", lazy=True)

class Challenge(db.Model):
    __tablename__          = "challenges"
    id                     = db.Column(db.Integer, primary_key=True)
    title                  = db.Column(db.String(120), nullable=False)
    description            = db.Column(db.Text,        nullable=False)
    category               = db.Column(db.String(50),  default="")
    difficulty             = db.Column(db.String(20),  default="medium")
    points                 = db.Column(db.Integer,     default=100)
    flag                   = db.Column(db.String(255), nullable=False)
    log_file_path          = db.Column(db.String(500), default="")
    sigma_rule             = db.Column(db.Text,        default="")
    answer_event_record_id = db.Column(db.String(50),  default="")
    status                 = db.Column(db.String(10),  default="draft")
    author_id              = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at             = db.Column(db.DateTime, default=datetime.utcnow)
    submissions            = db.relationship("Submission", backref="challenge", lazy=True)

class Submission(db.Model):
    __tablename__     = "submissions"
    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey("users.id"),      nullable=False)
    challenge_id      = db.Column(db.Integer, db.ForeignKey("challenges.id"), nullable=False)
    submitted_sigma   = db.Column(db.Text,        default="")
    matched_record_id = db.Column(db.String(50),  default="")
    is_correct        = db.Column(db.Boolean,     default=False)
    submitted_at      = db.Column(db.DateTime,    default=datetime.utcnow)
