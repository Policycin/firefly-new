from werkzeug.security import generate_password_hash, check_password_hash
from . import admin_login_manager
from flask_login import UserMixin, AnonymousUserMixin, current_user
from pymongo import MongoClient
from bson.objectid import ObjectId
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, redirect, url_for
from datetime import datetime
from markdown import markdown
import bleach


def generate_reset_password_confirmation_token(email, expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'password_reset': email})


def generate_change_email_confirmation_token(email, expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'change_email': email})


# 加密
def encrypt_passowrd(password):
    return generate_password_hash(password)


# 解密
def verify_password(user_password, password):
    return check_password_hash(user_password, password)


@admin_login_manager.user_loader
def load_user(user_id):
    user = MongoClient().blog.User.find_one({'_id': ObjectId(user_id)})
    return Temp(id=user.get('_id'), username=user.get('username'), email=user.get('email'),
                password=user.get('password'), activate=user.get('activate'), role=user.get('role'),
                name=user.get('name'),
                location=user.get('location'), about_me=user.get('about_me'), last_since=user.get('last_since'),
                member_since=user.get('member_since'))


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Admin:
    def __init__(self, username, email, password, name, pid, addtime):
        self.username = username
        self.email = email
        self.password_hash = encrypt_passowrd(password)
        self.db = MongoClient().FireFly.Admin
        self.name = name
        self.pid = pid
        self.addtime = addtime

    def new_user(self):
        collection = {
            'username': self.username,
            'email': self.email,
            'password': self.password_hash,
            'activate': False,
            'role': self.role,
            'name': self.name,
            'addtime': datetime.datetime.now(),
        }
        self.db.insert(collection)

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)

    def __repr__(self):
        return "<Admin %r>" % self.username
