from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, FileField
from flask_wtf import FlaskForm
from wtforms.validators import Required, Length, Email, DataRequired, ValidationError
from pymongo import MongoClient
from flask import current_app
from ..models import verify_password
from config import DevelopmentConfig

condev = DevelopmentConfig()
mongoIP = condev.MONGOIP
mongoPort = condev.MONGOPORT
db = MongoClient(mongoIP, port=mongoPort)
db = db.FireFly2


class LoginForm(FlaskForm):
    account = StringField(
        label='账号',
        validators=[
            DataRequired("请输入账号!")
        ],
        description='账号',
        render_kw={
            'class': 'form-control username',
            'placeholder': '请输入账号',
            'required': 'required'
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[
            DataRequired("请输入密码!")
        ],
        description="密码",
        render_kw={
            'class': 'form-control password',
            'placeholder': '请输入密码',
            'required': 'required'
        }
    )
    submit = SubmitField(
        '登陆',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat submitBtn',

        }
    )
    remember_me = BooleanField('保持登录')

    def validate_account(self, filed):
        account = filed.data
        user = db.Admin.find_one({'username': account})
        if not user:
            raise ValidationError("账号不存在")


# 首页督办文件选项的form表单
class IndexForm(FlaskForm):
    keyWord = StringField(
        label='关键字',
        description='关键字',
        # validators=[
        #     DataRequired("请输入关键字!")
        # ],
        render_kw={
            'class': 'search_input',
            'placeholder': '输入要检索的关键字',

        }
    )

    submitBtn = SubmitField(
        '开始检索',
        render_kw={
            'class': 'search_btn'
        }
    )


# 首页督办文件选项的form表单
class DbwjForm(FlaskForm):
    keyWord = StringField(
        label='关键字',
        description='关键字',
        validators=[
            DataRequired("请输入关键字!")
        ],
        render_kw={
            'class': 'form-control',
            'placeholder': '输入要检索的关键字',
            'required': 'required'
        }
    )

    submit = SubmitField(
        '二次检索',
        render_kw={
            'class': 'btn btn_default'
        }
    )


# 首页督办文件选项的form表单
class XzqhForm(FlaskForm):
    keyWord = StringField(
        label='关键字',
        description='关键字',
        validators=[
            DataRequired("请输入关键字!")
        ],
        render_kw={
            'class': 'form-control',
            'placeholder': '输入要检索的关键字',
            'required': 'required'
        }
    )

    submit = SubmitField(
        '二次检索',
        render_kw={
            'class': 'btn btn_default'
        }
    )
