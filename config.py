# coding:utf8
import os


class Config:
    SECRET_KEY = os.environ.get("SECTRET_KYE") or "PASSWORD"
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    # MONGOIP = '192.168.253.6'
    MONGOIP = '127.0.0.1'
    MONGOPORT = 27017
    MONGODBNAME = 'FireFly2'


config = {
    'development': DevelopmentConfig,
    'default': DevelopmentConfig
}
