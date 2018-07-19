# coding:utf8
from flask import Flask, render_template
from flask_login import LoginManager
import pymysql, os

app = Flask(__name__)
# db = SQLAlchemy(app)
app.debug = True
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:root@127.0.0.1:3306/movie"
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SECRET_KEY"] = "d1ab3701ec46491c8979b43562975666"
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/upload/')
app.config['MONGODBADDRESS'] = '192.168.253.6'
app.config['MONGODBPORT'] = 27017

admin_login_manager = LoginManager()
admin_login_manager.session_protection = 'strong'
admin_login_manager.login_view = 'admin.login'
admin_login_manager.init_app(app)

user_login_manager = LoginManager()
user_login_manager.session_protection = 'strong'
user_login_manager.login_view = 'home.login'
user_login_manager.init_app(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("home/404.html"), 404
