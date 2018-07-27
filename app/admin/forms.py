from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, FileField, \
    IntegerField, SelectMultipleField
from flask_wtf import FlaskForm
from wtforms.validators import Required, Length, Email, DataRequired, ValidationError, EqualTo
from pymongo import MongoClient
from ..models import verify_password
from app import app
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
            DataRequired("请输入账号")
        ],
        description='账号',
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入账号！',
            'required': 'required'
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[
            DataRequired("请输入密码")
        ],
        description="密码",
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入密码',
            'required': 'required'
        }
    )
    submit = SubmitField(
        '登陆',
        render_kw={
            'class': 'btn btn-primary btn-block btn-flat',

        }
    )
    remember_me = BooleanField('保持登录')

    def validate_account(self, filed):
        account = filed.data
        admin = db.Admin.find_one({'username': account})
        if not admin:
            raise ValidationError("账号不存在")


class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label='旧密码',
        validators=[
            DataRequired("请输入旧密码")
        ],
        description="旧密码",
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入旧密码',
            'required': 'required'
        }
    )
    new_pwd = PasswordField(
        label='新密码',
        validators=[
            DataRequired("请输入新密码")
        ],
        description="新密码",
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入新密码',
            'required': 'required'
        }
    )
    submit = SubmitField(
        '编辑',
        render_kw={
            'class': 'btn btn-primary',
        }
    )

    def validate_old_pwd(self, field):
        pwd = field.data
        from flask import session
        name = session['admin']
        admin = db.Admin.find_one({'username': name})
        if not verify_password(admin.get('password'), pwd):
            raise ValidationError("旧密码错误")


class TagForm(FlaskForm):
    name = StringField(
        label='标签名称',
        validators=[
            DataRequired("请输入标签名称")
        ],
        description="标签名称",
        render_kw={
            'class': "form-control",
            'id': 'input_name',
            'placeholder': '请输入标签名称！'
        }

    )
    submit = SubmitField(
        '编辑',
        render_kw={
            'class': 'btn btn-primary',

        }
    )


class SoureFileForm(FlaskForm):
    indexNum = StringField(
        label='索引号',
        validators=[
            DataRequired('请输入索引号')
        ],
        description='索引号',
        render_kw={
            'class': "form-control", 'placeholder': "请输入索引号！"
        }
    )
    fileType = StringField(
        label='主题分类',
        validators=[
            DataRequired('请输入主题分类')
        ],
        description='主题分类',
        render_kw={
            'class': "form-control", 'placeholder': "请输入主题分类！"
        }
    )
    publisher = StringField(
        label='发布机构',
        validators=[
            DataRequired('请输入发布机构')
        ],
        description='发布机构',
        render_kw={
            'class': "form-control", 'placeholder': "请输入发布机构！"
        }
    )
    createTime = StringField(
        label='生成时间',
        validators=[
            DataRequired('请选择生成时间')
        ],
        description='生成时间',
        render_kw={
            'class': "form-control", 'placeholder': "请选择生成时间！", "id": "input_release_time"
        }
    )
    title = StringField(
        label='标题',
        validators=[
            DataRequired('请输入标题')
        ],
        description='标题',
        render_kw={
            'class': "form-control", 'placeholder': "请输入标题！"
        }
    )
    fileNo = StringField(
        label='发文字号',
        validators=[
            DataRequired('请输入发文字号')
        ],
        description='发文字号',
        render_kw={
            'class': "form-control", 'placeholder': "请输入发文字号！"
        }
    )
    publishDate = StringField(
        label='发布时间',
        validators=[
            DataRequired('请选择发布时间')
        ],
        description='发布时间',
        render_kw={
            'class': "form-control", 'placeholder': "请选择发布时间！", "id": "input_release_time2"
        }
    )
    addtime = StringField(
        label='添加时间',
        validators=[
            DataRequired('请选择添加时间')
        ],
        description='添加时间',
        render_kw={
            'class': "form-control", 'placeholder': "请选择添加时间！", "id": "input_release_time3"
        }
    )
    tags = db.Tag.find().sort("_id", -1)
    tagc = []
    for v in range(tags.count()):
        tagc.append((tags[v].get("name"), tags[v].get("name")))
    tag_id = SelectField(
        label="标签",
        validators=[
            DataRequired('请选择标签')
        ],
        description='标签',
        coerce=str,
        choices=tagc,
        render_kw={
            "class": "form-control", "placeholder": "请选择标签分类"
        }
    )
    # path = FileField(
    #     label="本地文件",
    #     validators=[
    #         DataRequired('上传文件')
    #     ],
    #     description="本地文件"
    # )
    content = TextAreaField(
        label="内容",
        validators=[
            DataRequired('请输入内容')
        ],
        description='内容',
        render_kw={
            'class': "form-control", 'rows': "10", 'id': "input_info"
        }
    )
    url = StringField(
        label='原文链接',
        validators=[
            DataRequired('请输入原文链接')
        ],
        description='原文链接',
        render_kw={
            'class': "form-control", 'placeholder': "请输入原文链接！"
        }
    )
    submit = SubmitField(
        '编辑',
        render_kw={
            'class': 'btn btn-primary',

        }
    )


class CmpFileForm(FlaskForm):
    indexNum = StringField(
        label='索引号',
        validators=[
            DataRequired('请输入索引号！')
        ],
        description='索引号',
        render_kw={
            'class': "form-control", 'placeholder': "请输入索引号！"
        }
    )
    classfication = StringField(
        label='主题分类',
        validators=[
            DataRequired('请输入主题分类！')
        ],
        description='主题分类',
        render_kw={
            'class': "form-control", 'placeholder': "请输入主题分类！"
        }
    )
    publisher = StringField(
        label='发布机构',
        validators=[
            DataRequired('请输入发布机构！')
        ],
        description='发布机构',
        render_kw={
            'class': "form-control", 'placeholder': "请输入发布机构！"
        }
    )
    fileCreateTime = StringField(
        label='生成时间',
        validators=[
            DataRequired('请选择生成时间！')
        ],
        description='生成时间',
        render_kw={
            'class': "form-control", 'placeholder': "请选择生成时间！", "id": "input_release_time"
        }
    )
    fileName = StringField(
        label='标题',
        validators=[
            DataRequired('请输入标题！')
        ],
        description='标题',
        render_kw={
            'class': "form-control", 'placeholder': "请输入标题！"
        }
    )
    fileNo = StringField(
        label='发文字号',
        validators=[
            DataRequired('请输入发文字号！')
        ],
        description='发文字号',
        render_kw={
            'class': "form-control", 'placeholder': "请输入发文字号！"
        }
    )
    publishDate = StringField(
        label='发布日期',
        validators=[
            DataRequired('请选择发布日期！')
        ],
        description='发布日期',
        render_kw={
            'class': "form-control", 'placeholder': "请选择发布日期！", "id": "input_release_time2"
        }
    )
    addtime = StringField(
        label='添加时间',
        validators=[
            DataRequired('请选择添加时间！')
        ],
        description='添加时间',
        render_kw={
            'class': "form-control", 'placeholder': "请选择添加时间！", "id": "input_release_time3"
        }
    )
    tags = db.Tag.find().sort("_id", -1)
    tagc = []
    for v in range(tags.count()):
        tagc.append((tags[v].get("name"), tags[v].get("name")))
    tag_id = SelectField(
        label="标签",
        validators=[
            DataRequired('请选择标签！')
        ],
        description='标签',
        coerce=str,
        choices=tagc,
        render_kw={
            "class": "form-control", "placeholder": "请选择标签分类！"
        }
    )
    content = TextAreaField(
        label="内容",
        validators=[
            DataRequired('请输入正文！')
        ],
        description='内容',
        render_kw={
            'class': "form-control", 'rows': "10", 'id': "input_info"
        }
    )
    fileWebsiteUrl = StringField(
        label='原文链接',
        validators=[
            DataRequired('请输入原文链接！')
        ],
        description='原文链接',
        render_kw={
            'class': "form-control", 'placeholder': "请输入原文链接！"
        }
    )
    abolitionDate = StringField(
        label='废止日期',
        validators=[
            DataRequired("请选择废止日期！")
        ],
        description='废止日期',
        render_kw={
            'class': "form-control", 'placeholder': "请选择添加时间！", "id": "input_release_time4"
        }
    )
    fileLocalUrl = StringField(
        label='本地路径',
        validators=[
            DataRequired("请输入本地路径！")
        ],
        description='本地路径',
        render_kw={
            'class': "form-control", 'placeholder': "请输入本地路径！"
        }
    )
    fromDate = StringField(
        label='生效日期',
        validators=[
            DataRequired("请选择生效日期！")
        ],
        description='生效日期',
        render_kw={
            'class': "form-control", 'placeholder': "请选择添加时间！", "id": "input_release_time5"
        }
    )
    keyword = StringField(
        label='关键词',
        validators=[
            DataRequired("请输入关键词！")
        ],
        description='关键词',
        render_kw={
            'class': "form-control", 'placeholder': "请输入关键词！"
        }
    )
    publisherCityName = StringField(
        label='城市名称',
        validators=[
            DataRequired("请输入城市名称！")
        ],
        description='城市名称',
        render_kw={
            'class': "form-control", 'placeholder': "请输入城市名称！"
        }
    )
    submit = SubmitField(
        '编辑',
        render_kw={
            'class': 'btn btn-primary',

        }
    )


class NoticeForm(FlaskForm):
    content = StringField(
        label='公告',
        validators=[
            DataRequired("请输入公告信息")
        ],
        description="公告",
        render_kw={
            'class': "form-control",
            'id': 'input_name',
            'placeholder': '请输入公告信息！'
        }

    )
    cho = [('是', '是'), ('否', '否')]
    activation = SelectField(
        label="是否生效",
        validators=[
            DataRequired('请选择是否生效')
        ],
        description='是否生效',
        coerce=str,
        choices=cho,
        render_kw={
            "class": "form-control", "placeholder": "请选择标签分类"
        }
    )
    submit = SubmitField(
        '编辑',
        render_kw={
            'class': 'btn btn-primary',

        }
    )


class CalForm(FlaskForm):
    sourefileNo = SelectField(
        label="国发文号",
        validators=[
            DataRequired()
        ],
        description="国发文号",
        coerce=str,
        render_kw={
            "class": "form-control", "placeholder": "请选择国发文号"
        }
    )

    submit = SubmitField(
        '下一步',
        render_kw={
            'class': 'btn btn-primary',

        }

    )


class SentenceForm(FlaskForm):
    sentence = StringField(
        label="语句",
        validators=[
            DataRequired()
        ],
        description="语句",
        render_kw={
            "class": "form-control", "placeholder": "请输入语句"
        }
    )
    threshold = StringField(
        label="阈值",
        validators=[
            DataRequired()
        ],
        description="阈值",
        render_kw={
            "class": "form-control", "placeholder": "请输入阈值"
        }
    )
    weight = IntegerField(
        label="权重",
        validators=[
            DataRequired()
        ],
        description="权重",
        render_kw={
            "class": "form-control", "placeholder": "请输入权重"
        }
    )
    submit = SubmitField(
        '保存',
        render_kw={
            'class': 'btn btn-primary',
        }
    )


class AuthForm(FlaskForm):
    auth = StringField(
        label="权限",
        validators=[
            DataRequired("请输入权限名称！")
        ],
        description="权限",
        render_kw={
            "class": "form-control", "placeholder": "请输入名称"
        }
    )
    url = StringField(
        label="路径",
        validators=[
            DataRequired("请输入路径！")
        ],
        description="路径",
        render_kw={
            "class": "form-control", "placeholder": "请输入路径"
        }
    )
    submit = SubmitField(
        '保存',
        render_kw={
            'class': 'btn btn-primary',
        }
    )


class RoleForm(FlaskForm):
    name = StringField(
        label="角色名称",
        validators=[
            DataRequired("请输入角色名称")
        ],
        description="角色名称",
        render_kw={
            "class": "form-control", "placeholder": "请输入角色名称"
        }
    )
    auths = SelectMultipleField(
        label="权限列表",
        validators=[
            DataRequired("权限列表不能为空！")
        ],
        # 动态数据填充选择栏：列表生成器
        coerce=str,
        choices=[(v["url"], v["auth"]) for v in db.Auth.find()],
        description="权限列表",
        render_kw={
            "class": "form-control",
        }
    )
    submit = SubmitField(
        '保存',
        render_kw={
            'class': 'btn btn-primary',
        }
    )


class AdminForm(FlaskForm):
    name = StringField(
        label="昵称",
        validators=[
            DataRequired("请输入昵称")
        ],
        description="昵称",
        render_kw={
            "class": "form-control", "placeholder": "请输入昵称"
        }
    )
    username = StringField(
        label="用户名",
        validators=[
            DataRequired("请输入用户名")
        ],
        description="用户名",
        render_kw={
            "class": "form-control", "placeholder": "请输入用户名"
        }
    )
    pwd = PasswordField(
        label='密码',
        validators=[
            DataRequired("请输入密码")
        ],
        description="密码",
        render_kw={
            'class': 'form-control',
            'placeholder': '请输入密码',
            'required': 'required'
        }
    )
    repwd = PasswordField(
        label='重复密码',
        validators=[
            DataRequired("请再次输入密码"),
            EqualTo('pwd', message="两次密码不一致！")
        ],
        description="重复密码",
        render_kw={
            'class': 'form-control',
            'placeholder': '请再次输入新密码',
            'required': 'required'
        }
    )
    role = SelectField(
        label="管理员角色",
        coerce=str,
        choices=[(v["name"], v["name"]) for v in db.Role.find()],
        render_kw={
            'class': 'form-control'
        }

    )
    email = StringField(
        label="邮箱",
        validators=[
            DataRequired("邮箱不能为空！"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入邮箱！",
        }
    )
    submit = SubmitField(
        '保存',
        render_kw={
            'class': 'btn btn-primary',
        }
    )


class UserForm(FlaskForm):
    # name=StringField(
    #     lable="昵称",
    #     validators=[
    #         DataRequired("请输入昵称")
    #     ],
    #     description="昵称",
    #     render_kw={
    #         "class": "form-control", "placeholder": "请输入昵称"
    #     }
    # )
    username = StringField(
        lable="用户名",
        validators=[
            DataRequired("请输入用户名")
        ],
        description="用户名",
        render_kw={
            "class": "form-control", "placeholder": "请输入用户名"
        }
    )

    def validate_username(self, field):
        username = field.data
        user = db.User.find_one().count()
        if user == 1:
            raise ValidationError("该用户名已存在")

    # pwd = PasswordField(
    #     label='密码',
    #     validators=[
    #         DataRequired("请输入密码")
    #     ],
    #     description="密码",
    #     render_kw={
    #         'class': 'form-control',
    #         'placeholder': '请输入密码',
    #         'required': 'required'
    #     }
    # )
    # email = StringField(
    #     label="邮箱",
    #     validators=[
    #         DataRequired("邮箱不能为空！"),
    #         Email("邮箱格式不正确！")
    #     ],
    #     description="邮箱",
    #     render_kw={
    #         "class": "form-control input-lg",
    #         "placeholder": "请输入邮箱！",
    #     }
    # )
    submit = SubmitField(
        '保存',
        render_kw={
            'class': 'btn btn-primary',
        }
    )
