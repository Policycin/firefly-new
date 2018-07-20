from . import admin
from .bot import bot
from elasticsearch import Elasticsearch
from flask import render_template, redirect, url_for, flash, session, request
from .forms import LoginForm, TagForm, PwdForm, SoureFileForm, CmpFileForm, NoticeForm, SentenceForm
from pymongo import MongoClient, DESCENDING
from ..models import verify_password
from flask_login import login_user, logout_user, login_required, current_user
import os, datetime, uuid, re
from urllib.parse import urlencode, quote, unquote
from bson.objectid import ObjectId
from functools import wraps
from config import DevelopmentConfig
from .Caculate import Likelihood

# from multiprocessing import Pool, Process, Queue
# pool = Pool(processes=4)
condev = DevelopmentConfig()
mongoIP = condev.MONGOIP
mongoPort = condev.MONGOPORT
db = MongoClient(mongoIP, port=mongoPort)
db = db.FireFly2
es = Elasticsearch("http://127.0.0.1:9200/")


@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


# 登陆装饰器
def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@admin.route('/')
@admin_login_req
def index():
    return render_template('admin/index.html')


@admin.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = db.Admin.find_one({"username": data['account']})
        print(admin)
        if admin is not None and verify_password(admin.get('password'), data['pwd']):
            session['admin'] = data['account']
            return redirect(url_for('admin.index'))
        elif not verify_password(admin.get('password'), data['pwd']):
            flash("密码错误!", 'err')
            return redirect(url_for('admin.login'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
def logout():
    session.pop('admin', None)
    # session.pop('admin_id', None)
    session.clear()
    return redirect(url_for('admin.login'))


@admin.route('/pwd/', methods=['GET', 'POST'])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = db.Admin.find_one({'username': session['admin']})
        from werkzeug.security import generate_password_hash
        newadmin = admin
        newpwd = generate_password_hash(data['new_pwd'])
        db.Admin.update(admin, {'$set': {'password': newpwd}})
        flash("密码修改成功", 'ok')
        redirect(request.args.get('next') or url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


# 标签管理
@admin.route('/tag/add/', methods=["GET", "POST"])
@admin_login_req
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = db.Tag.find_one({'name': data['name']})
        if tag:
            flash("该标签已存在", 'err')
            return redirect(url_for('admin.tag_add'))
        tag = {
            'name': data['name'].replace(" ", "").strip(),
            'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
        db.Tag.insert(tag)
        flash("添加成功", 'ok')

        # tag = db.Tag.find().sort('_id', -1)
        # count = tag.count()
        # paper_obj = Pagination(request.args.get("page", 1), count, request.path, request.args, per_page_count=10)
        # html = paper_obj.page_html()
        # param = []
        # for v in range(count):
        #     param.append([tag[v].get("_id"), tag[v].get("name"), tag[v].get("addtime")])
        # index_list = param[paper_obj.start:paper_obj.end]
        return redirect(url_for('admin.tag_list'))
    return render_template("admin/tag_add.html", form=form)


@admin.route('/tag/list/', methods=["GET"])
@admin_login_req
def tag_list(page=None):
    page = request.args.get("page")
    if page == None:
        page = 1
    # 跳转列表页
    page = int(page)
    per_page_count = 10
    tag = db.Tag.find().sort('_id', -1).limit(10).skip(per_page_count * (page - 1))
    tagcount = tag.count()
    tagparam = []
    i = 1 + (page - 1) * per_page_count
    for v in tag:
        tagparam.append([i, v["_id"], v["name"], v["addtime"]])
        i += 1
    paper_obj = Pagination(request.args.get("page", page), tagcount, request.path, request.args,
                           per_page_count=per_page_count)
    html = paper_obj.page_html()
    index_list = tagparam[0:per_page_count + 1]
    return render_template("admin/tag_list.html", index_list=index_list, html=html)


@admin.route('/tag/del/<id>/', methods=["GET"])
@admin_login_req
def tag_del(id=None):
    db.Tag.remove({'_id': ObjectId(id)})
    flash("标签删除成功", 'del')
    return redirect(url_for('admin.tag_list'))


@admin.route('/tag/edit/<id>/', methods=["GET", "POST"])
@admin_login_req
def tag_edit(id=None):
    form = TagForm()
    tag = db.Tag.find_one({'_id': ObjectId(id)})
    if form.validate_on_submit():
        data = form.data
        tag_count = db.Tag.find_one({'name': data['name']})
        if tag_count and tag['name'] != data['name']:
            flash("该标签已存在", 'err')
            return redirect(url_for('admin.tag_edit', id=id))
        newtag = data['name']
        db.Tag.update(tag, {'$set': {'name': newtag}})
        flash("更新成功", 'ok')
        return redirect(url_for('admin.tag_edit', id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


# 源文件管理
@admin.route('/sourefile/add/', methods=['GET', 'POST'])
def sourefile_add():
    form = SoureFileForm()
    if form.validate_on_submit():
        data = form.data
        sourefile = db.SoureFile.find_one({'title': data['title']} or {'indexNum': data['indexNum']}
                                          or {'fileNo': data['fileNo']})
        if sourefile:
            flash("该源文件已存在", 'err')
            return redirect(url_for('admin.sourefile_add'))
        xxx = ""
        if data['content'] is not None:
            for x in data['content']:
                x = "".join(x.split())
                if x != "":
                    xxx += x
        sourefile = {
            'indexNum': data['indexNum'].replace(" ", "").strip(),
            'fileType': data['fileType'].replace(" ", "").strip(),
            'publisher': data['publisher'].replace(" ", "").strip(),
            'createTime': data['createTime'].replace(" ", "").strip(),
            'title': data['title'].replace(" ", "").strip(),
            'fileNo': data['fileNo'].replace(" ", "").strip(),
            'publishDate': data['publishDate'].replace(" ", "").strip(),
            'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            # 'path':r"\\",
            'content': xxx.replace(" ", "").strip(),
            'tag': data['tag_id'].replace(" ", "").strip(),
            'url': data['url'].replace(" ", "").strip()
        }
        db.SoureFile.insert(sourefile)
        flash("添加成功", 'ok')
        return redirect(url_for('admin.sourefile_list'))
    return render_template('admin/sourefile_add.html', form=form)


@admin.route('/sourefile/list/')
def sourefile_list(page=None):
    page = request.args.get("page")
    if page == None:
        page = 1
    page = int(page)

    # 跳转列表页
    per_page_count = 10
    sourefile = db.SoureFile.find().sort('_id', -1).limit(10).skip(per_page_count * (page - 1))
    count = sourefile.count()
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args,
                           per_page_count=per_page_count)
    html = paper_obj.page_html()
    param = []
    i = 1 + (page - 1) * per_page_count
    for v in sourefile:
        param.append([i, v["_id"], v['indexNum'], v["title"],
                      v["publisher"],
                      v["tag"],
                      v["publishDate"],
                      v["url"]
                      ])
        i += 1
    index_list = param[0:per_page_count + 1]
    return render_template('admin/sourefile_list.html', index_list=index_list, html=html)


@admin.route('/sourefile/del/<id>/', methods=['GET'])
def sourefile_del(id=None):
    db.SoureFile.remove({'_id': ObjectId(id)})
    flash("标签删除成功", 'del')
    return redirect(url_for('admin.sourefile_list'))


@admin.route('/sourefile/edit/<id>/', methods=['GET', 'POST'])
def sourefile_edit(id=None):
    form = SoureFileForm()
    sourefile = db.SoureFile.find_one({'_id': ObjectId(id)})
    if request.method == 'GET':
        form.tag_id.data = sourefile['tag']
        form.content.data = sourefile['content']

    if form.validate_on_submit():
        data = form.data
        sourefilecur = db.SoureFile.find_one({'title': data['title']} or {'indexNum': data['indexNum']}
                                             or {'fileNo': data['fileNo']})
        if sourefilecur and (
                sourefile['title'] != data['title'] or sourefile['indexNum'] != data['indexNum'] or sourefile[
            'fileNo'] != data['fileNo']):
            flash('该源文件已存在', 'err')
            return redirect(url_for('admin.sourefile_edit', id=id))
        newsourefile = {
            'indexNum': data['indexNum'].replace(" ", "").strip(),
            'fileType': data['fileType'].replace(" ", "").strip(),
            'publisher': data['publisher'].replace(" ", "").strip(),
            'createTime': data['createTime'].replace(" ", "").strip(),
            'title': data['title'].replace(" ", "").strip(),
            'fileNo': data['fileNo'].replace(" ", "").strip(),
            'publishDate': data['publishDate'].replace(" ", "").strip(),
            'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            # 'path':r"\\",
            'content': data['content'].replace(" ", "").strip(),
            'tag': data['tag_id'].replace(" ", "").strip(),
            'url': data['url'].replace(" ", "").strip()
        }
        db.SoureFile.update(sourefile, {"$set": newsourefile})
        flash('更新成功', 'ok')
        return redirect(url_for('admin.sourefile_edit', id=id))
    return render_template('admin/sourefile_edit.html', form=form, sourefile=sourefile)


@admin.route('/cmpfile/add/', methods=['GET', 'POST'])
def cmpfile_add():
    form = CmpFileForm()
    if form.validate_on_submit():
        data = form.data
        sourefile = db.CmpFile.find_one({'fileName': data['fileName']} or {'indexNum': data['indexNum']}
                                        or {'fileNo': data['fileNo']})
        if sourefile:
            flash("该文件已存在", 'err')
            return redirect(url_for('admin.cmpfile_add'))
        # 分句
        content = data['content']
        content = content.strip()
        content = content.replace(" ", "")
        patterQiantou = re.compile(r'(().*?牵头.*?())')
        patterFuze = re.compile(r'(().*?负责.*?())')
        patterGuofa = re.compile(r'(().*?国发.*?())')
        strSub = re.split(r"。|；|;|）|（|:|：", content)
        sentences = []
        if strSub is not None:
            for x in strSub:
                x = "".join(x.split())
                if len(x) > 3 and x != "":
                    if patterFuze.search(x) is not None:
                        continue
                    if patterQiantou.search(x) is not None:
                        continue
                    if patterGuofa.search(x) is not None:
                        continue
                    sentences.append(x)

        xxx = ""
        if data['content'] is not None:
            for x in data['content']:
                x = "".join(x.split())
                if x != "":
                    xxx += x
        cmpfile = {
            'indexNum': data['indexNum'].replace(" ", "").strip(),
            'classfication': data['classfication'].replace(" ", "").strip(),
            'publisher': data['publisher'].replace(" ", "").strip(),
            'fileCreateTime': data['fileCreateTime'],
            'fileName': data['fileName'].replace(" ", "").strip(),
            'fileNo': data['fileNo'].replace(" ", "").strip(),
            'publishDate': data['publishDate'],
            'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'content': xxx.replace(" ", "").strip(),
            'tag': data['tag_id'],
            'fileWebsiteUrl': data['fileWebsiteUrl'].replace(" ", "").strip(),
            'abolitionDate': data['abolitionDate'],
            'fileLocalUrl': data['fileLocalUrl'].replace(" ", "").strip(),
            'fromDate': data['fromDate'],
            'keyword': data['keyword'].replace(" ", "").strip(),
            'publisherCityName': data['publisherCityName'].replace(" ", "").strip(),
            'contents': sentences
        }
        db.CmpFile.insert(cmpfile)
        flash("添加成功", 'ok')
        return redirect(url_for('admin.cmpfile_list'))
    return render_template('admin/cmpfile_add.html', form=form)


@admin.route('/cmpfile/list/<int:page>')
def cmpfile_list(page=None):
    per_page_count = 10
    page = request.args.get("page")
    if page == None:
        page = 1
    page = int(page)
    # 跳转列表页
    cmpfile = db.CmpFile.find().sort('_id', -1).limit(per_page_count).skip(per_page_count * (page - 1))
    count = cmpfile.count()
    if not count:
        return redirect(url_for("admin.cmpfile_add"))
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args, per_page_count=10)
    html = paper_obj.page_html()
    param = []

    i = (page - 1) * per_page_count + 1
    for v in cmpfile:
        param.append([i, v["_id"], v['fileName'], v["publisher"],
                      v["publishDate"],
                      v["publisherCityName"],
                      v["fileWebsiteUrl"],
                      ])
    index_list = param[0:per_page_count + 1]
    return render_template('admin/cmpfile_list.html', index_list=index_list, html=html)


@admin.route('/cmpfile/del/<id>', methods=['GET'])
def cmpfile_del(id=None):
    db.CmpFile.remove({'_id': ObjectId(id)})
    flash("标签删除成功", 'del')
    return redirect(url_for('admin.cmpfile_list', page=1))


@admin.route('/cmpfile/edit/<id>', methods=['GET', 'POST'])
def cmpfile_edit(id=None):
    form = CmpFileForm()
    cmpfile = db.CmpFile.find_one({'_id': ObjectId(id)})
    if request.method == 'GET':
        form.tag_id.data = cmpfile['tag']
        form.content.data = cmpfile['content']

    if form.validate_on_submit():
        data = form.data
        cmpfilecur = db.SoureFile.find_one({'fileName': data['fileName']} or {'indexNum': data['indexNum']}
                                           or {'fileNo': data['fileNo']})
        if cmpfilecur and (
                cmpfile['fileName'] != data['fileName'] or cmpfile['indexNum'] != data['indexNum'] or cmpfile[
            'fileNo'] != data['fileNo']):
            flash('该源文件已存在', 'err')
            return redirect(url_for('admin.cmpfile_edit', id=id))
        newcmpfile = {
            'indexNum': data['indexNum'].replace(" ", "").strip(),
            'classfication': data['classfication'].replace(" ", "").strip(),
            'publisher': data['publisher'].replace(" ", "").strip(),
            'fileCreateTime': data['fileCreateTime'],
            'fileName': data['fileName'].replace(" ", "").strip(),
            'fileNo': data['fileNo'].replace(" ", "").strip(),
            'publishDate': data['publishDate'],
            'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'content': data['content'].replace(" ", "").strip(),
            'tag': data['tag_id'].replace(" ", "").strip(),
            'fileWebsiteUrl': data['fileWebsiteUrl'].replace(" ", "").strip(),
            'abolitionDate': data['abolitionDate'],
            'fileLocalUrl': data['fileLocalUrl'].replace(" ", "").strip(),
            'fromDate': data['fromDate'],
            'keyword': data['keyword'].replace(" ", "").strip(),
            'publisherCityName': data['publisherCityName'].replace(" ", "").strip()
        }
        db.CmpFile.update(cmpfile, {"$set": newcmpfile})
        flash('更新成功', 'ok')
        return redirect(url_for('admin.cmpfile_edit', id=id))
    return render_template('admin/cmpfile_edit.html', form=form, cmpfile=cmpfile)


# 公告管理
@admin.route('/notice/list/<int:page>')
def notice_list(page=None):
    per_page_count = 10
    page = request.args.get("page")
    if page == None:
        page = 1
    page = int(page)
    notice = db.Notice.find().sort('_id', -1).limit(per_page_count).skip(per_page_count * (page - 1))
    count = notice.count()
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args,
                           per_page_count=per_page_count)
    html = paper_obj.page_html()
    param = []
    i = (page - 1) * per_page_count + 1
    for v in notice:
        param.append([i, v["_id"], v["content"], v["activation"],
                      v["optuser"], v["addtime"]])
    index_list = param[0:per_page_count + 1]
    return render_template("admin/notice_list.html", index_list=index_list, html=html)


@admin.route('/notice/add/', methods=['GET', 'POST'])
def notice_add():
    form = NoticeForm()
    if form.validate_on_submit():
        data = form.data
        notice = {
            'content': data['content'].replace(" ", "").strip(),
            'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            'optuser': session['admin'],
            'activation': data['activation']
        }
        db.Notice.insert(notice)
        flash("添加成功", 'ok')
        return redirect(url_for('admin.notice_list', page=1))
    return render_template('admin/notice_add.html', form=form)


@admin.route('/notice/del/<id>', methods=['GET'])
def notice_del(id=None):
    db.Notice.remove({"_id": ObjectId(id)})
    flash("公告删除成功", 'del')
    return redirect(url_for('admin.notice_list', page=1))


@admin.route('/notice/edit/<id>', methods=['GET', 'POST'])
def notice_edit(id=None):
    form = NoticeForm()
    notice = db.Notice.find_one({"_id": ObjectId(id)})
    if request.method == 'GET':
        form.activation.data = notice['activation']
    if form.validate_on_submit():
        data = form.data
        newnotice = {
            'content': data['content'],
            'activation': data['activation']
        }

        db.Notice.update(notice, {'$set': newnotice})
        flash("更新成功", 'ok')
        return redirect(url_for('admin.notice_edit', id=id))
    return render_template("admin/notice_edit.html", form=form, notice=notice)


# 相似度计算
@admin.route("/bot/search/")
def bot_search():
    sourefile = db.SoureFile.find().sort(" _id", -1)
    return render_template("admin/bot_search.html", sourefile=sourefile)


@admin.route('/bot/list/<int:page>')
def bot_list(page=None):
    sourefileNo = request.args.get("sourefileNo")
    fileNo = request.args.get("fileNo")
    fileTitle = request.args.get("fileTitle")
    fileCityName = request.args.get("fileCityName")
    fileReleasetime1 = request.args.get("fileReleasetime1")
    fileReleasetime2 = request.args.get("fileReleasetime2")
    # sourefile=[]
    # print(sourefileNo,fileNo,fileTitle,fileCityName,fileReleasetime1,fileReleasetime1)
    sourefile = db.SoureFile.find_one({"fileNo": sourefileNo})
    # 分句
    content = sourefile['content']
    content = content.strip()
    content = content.replace(" ", "")
    patterQiantou = re.compile(r'(().*?牵头.*?())')
    patterFuze = re.compile(r'(().*?负责.*?())')
    patterGuofa = re.compile(r'(().*?国发.*?())')
    strSub = re.split(r"。|；|;|）|（|:|：", content)
    sentences = []
    sqlwhereOne = []
    sqlwhereOne.append(sourefileNo)
    sqlwhereOne.append(fileNo)
    sqlwhereOne.append(fileTitle)
    sqlwhereOne.append(fileCityName)
    sqlwhereOne.append(fileReleasetime1)
    sqlwhereOne.append(fileReleasetime2)

    if strSub is not None:
        for x in strSub:
            x = "".join(x.split())
            if len(x) > 3 and x != "":
                if patterFuze.search(x) is not None:
                    continue
                if patterQiantou.search(x) is not None:
                    continue
                if patterGuofa.search(x) is not None:
                    continue
                sentences.append(x)
    # print(len(sentences))
    db.SoureFile.update_one({"fileNo": sourefileNo}, {"$set": {"sentenceArray": sentences}}, True, False)
    llt = db.SoureFile.find_one({"fileNo": sourefileNo})
    for v in range(len(sentences)):
        insertdata = {
            "text": sentences[v],
            "fileNo": sourefileNo,
            "threshold": "80",
            "created_at": datetime.datetime.today(),
            "weight": 1,
            "objId": int(v),
            "fileName": llt['title'],
            "uid": llt['_id']
        }
        flag = db.statements_all.find_one({"text": sentences[v]})
        if not flag:
            db.statements_all.update_one({"objId": int(v), "text": sentences[v]}, {"$set": insertdata}, True, False)
        # print("v=%s" % v)
    sqlwhere = {}
    if fileNo is not None and len(fileNo.strip()) > 0:
        sqlfileNo = {'fileNo': re.compile(fileNo)}
        sqlwhere.update(sqlfileNo)
    if fileTitle is not None and len(fileTitle.strip()) > 0:
        sqlfileTitle = {'fileName': re.compile(fileTitle)}
        sqlwhere.update(sqlfileTitle)
    if fileCityName is not None and len(fileCityName.strip()) > 0:
        sqlfileCityName = {'publisherCityName': re.compile(fileCityName)}
        sqlwhere.update(sqlfileCityName)
    if fileReleasetime1 is not None and len(fileReleasetime1.strip()) > 0:
        sqlfileReleasetime1 = {'publishDate': {"$gte": fileReleasetime1}}
        sqlwhere.update(sqlfileReleasetime1)
    else:
        fileReleasetime1 = ""
    if fileReleasetime2 is not None and len(fileReleasetime2.strip()) > 0:
        if len(fileReleasetime1.strip()) > 0:
            sqlfileReleasetime2 = {'publishDate': {"$gte": fileReleasetime1, "$lte": fileReleasetime2}}
        else:
            sqlfileReleasetime2 = {'publishDate': {"lte": fileReleasetime2}}
        sqlwhere.update(sqlfileReleasetime2)

    # 分页信息
    per_page_count = 10
    page = request.args.get("page")
    if page is None:
        page = 1
    page = int(page)
    entities = db.CmpFile.find(sqlwhere).limit(per_page_count).skip(per_page_count * (page - 1))
    count = entities.count()
    i = 1 + (page - 1) * per_page_count
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args,
                           per_page_count=per_page_count)
    html = paper_obj.page_html()
    param = []
    for v in entities:
        param.append([i, v["_id"], v["fileName"], v["publisherCityName"],
                      v["publisher"], v["publishDate"], v["fileWebsiteUrl"]])
    index_list = param[0:per_page_count + 1]

    sentences = db.statements_all.find({"fileNo": sourefileNo})
    return render_template('admin/bot_list.html', index_list=index_list, html=html, sentences=sentences,
                           sqlwhereOne=sqlwhereOne)


@admin.route("/bot/alert/", methods=["GET", "POST"])
def bot_alert():
    sourefileNo = request.args.get("sourefileNo")
    fileNo = request.args.get("fileNo")
    fileTitle = request.args.get("fileTitle")
    fileCityName = request.args.get("fileCityName")
    fileReleasetime1 = request.args.get("fileReleasetime1")
    fileReleasetime2 = request.args.get("fileReleasetime2")
    sentenceNo = request.args.get("sentenceId")
    sqlwhereOne = []
    sqlwhereOne.append(sourefileNo)
    sqlwhereOne.append(fileNo)
    sqlwhereOne.append(fileTitle)
    sqlwhereOne.append(fileCityName)
    sqlwhereOne.append(fileReleasetime1)
    sqlwhereOne.append(fileReleasetime2)
    sentences = db.statements_all.find({"fileNo": sourefileNo})

    form = SentenceForm()
    sqlwhere = {}
    if fileNo is not None and len(fileNo.strip()) > 0:
        sqlfileNo = {'fileNo': re.compile(fileNo)}
        sqlwhere.update(sqlfileNo)
    if fileTitle is not None and len(fileTitle.strip()) > 0:
        sqlfileTitle = {'fileName': re.compile(fileTitle)}
        sqlwhere.update(sqlfileTitle)
    if fileCityName is not None and len(fileCityName.strip()) > 0:
        sqlfileCityName = {'publisherCityName': re.compile(fileCityName)}
        sqlwhere.update(sqlfileCityName)
    if fileReleasetime1 is not None and len(fileReleasetime1.strip()) > 0:
        sqlfileReleasetime1 = {'publishDate': {"$gte": fileReleasetime1}}
        sqlwhere.update(sqlfileReleasetime1)
    else:
        fileReleasetime1 = ""
    if fileReleasetime2 is not None and len(fileReleasetime2.strip()) > 0:
        if len(fileReleasetime1.strip()) > 0:
            sqlfileReleasetime2 = {'publishDate': {"$gte": fileReleasetime1, "$lte": fileReleasetime2}}
        else:
            sqlfileReleasetime2 = {'publishDate': {"lte": fileReleasetime2}}
        sqlwhere.update(sqlfileReleasetime2)

    # 分页信息
    per_page_count = 10
    page = request.args.get("page")
    if page is None:
        page = 1
    page = int(page)
    entities = db.CmpFile.find(sqlwhere).limit(per_page_count).skip(per_page_count * (page - 1))
    count = entities.count()
    i = 1 + (page - 1) * per_page_count
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args,
                           per_page_count=per_page_count)
    html = paper_obj.page_html()
    param = []
    for v in entities:
        param.append([i, v["_id"], v["fileName"], v["publisherCityName"],
                      v["publisher"], v["publishDate"], v["fileWebsiteUrl"]])
    index_list = param[0:per_page_count + 1]

    if request.method == 'GET':
        form.sentence.data = db.statements_all.find_one({"fileNo": sourefileNo, "objId": int(sentenceNo)})['text']
        form.threshold.data = db.statements_all.find_one({"fileNo": sourefileNo, "objId": int(sentenceNo)})['threshold']
        form.weight.data = db.statements_all.find_one({"fileNo": sourefileNo, "objId": int(sentenceNo)})['weight']
    if form.validate_on_submit():
        data = form.data
        sentence = {
            'text': data['sentence'],
            'threshold': data['threshold'],
            'weight': data['weight']
        }
        upsentence = db.statements_all.find_one({"fileNo": sourefileNo, "objId": int(sentenceNo)})
        db.statements_all.update_one(upsentence, {'$set': sentence})
        # flash("修改成功", 'save')
        return render_template('admin/bot_list.html', index_list=index_list, html=html, sentences=sentences,
                               sqlwhereOne=sqlwhereOne)
    return render_template("admin/bot_alert.html", sqlwhereOne=sqlwhereOne, sentences=sentences, form=form,
                           objId=int(sentenceNo) + 1, index_list=index_list, html=html)


@admin.route('/bot/cal/')
def bot_cal():
    # 接收查询条件
    sourefileNo = request.args.get("sourefileNo")
    fileNo = request.args.get("fileNo")
    fileTitle = request.args.get("fileTitle")
    fileCityName = request.args.get("fileCityName")
    fileReleasetime1 = request.args.get("fileReleasetime1")
    fileReleasetime2 = request.args.get("fileReleasetime2")

    totalFileCount = 0
    totalRowCount = 0

    sentences = db.SoureFile.find_one({"fileNo": sourefileNo})
    sentences = sentences['sentenceArray']
    # sqlwhereOne = {}
    # db.statements.remove(sqlwhereOne)
    # sqlwhereOne = {'fileNo': id}
    # entities2 = db.statements_all.find(sqlwhereOne)
    # 存入临时变量--源文件及语句信息

    entities2 = db.statements_all.find({"fileNo": sourefileNo})
    db.statements.remove({})
    entities2Count = entities2.count()
    # print(entities2.count())
    # for x in range(entities2Count):
    # entitiesMap = entities2[x]
    # db.statements.insert_one(entitiesMap)

    # 查询所有符合条件的对比文件entities
    sqlwhere2 = {}
    if fileNo is not None and len(fileNo.strip()) > 0:
        sqlfileNo = {'fileNo': re.compile(fileNo)}
        sqlwhere2.update(sqlfileNo)
    if fileTitle is not None and len(fileTitle.strip()) > 0:
        sqlfileTitle = {'fileName': re.compile(fileTitle)}
        sqlwhere2.update(sqlfileTitle)
    if fileCityName is not None and len(fileCityName.strip()) > 0:
        sqlfileCityName = {'publisherCityName': re.compile(fileCityName)}
        sqlwhere2.update(sqlfileCityName)
    if fileReleasetime1 is not None and len(fileReleasetime1.strip()) > 0:
        sqlfileReleasetime1 = {'publishDate': {"$gte": fileReleasetime1}}
        sqlwhere2.update(sqlfileReleasetime1)
    else:
        fileReleasetime1 = ""
    if fileReleasetime2 is not None and len(fileReleasetime2.strip()) > 0:
        if len(fileReleasetime1.strip()) > 0:
            sqlfileReleasetime2 = {'publishDate': {"$gte": fileReleasetime1, "$lte": fileReleasetime2}}
        else:
            sqlfileReleasetime2 = {'publishDate': {"lte": fileReleasetime2}}
        sqlwhere2.update(sqlfileReleasetime2)
    entities = db.CmpFile.find(sqlwhere2)
    totalCount = entities.count()
    # entities   对比文件
    # entities2   源文件语句列表
    #
    patterDiqu = re.compile(r'(().*?各地区.*?())')
    patterBumen = re.compile(r'(().*?各部门.*?())')
    patterYouGuan = re.compile(r'(().*?各有关.*?())')
    if entities2Count > 1:
        # try:
        for x in range(totalCount):
            # 计算开始计时
            time1 = datetime.datetime.today()
            entitiesMap = entities[x]
            if (db.ConfidenceResult.find({"fileNo": sourefileNo, "uid2": entitiesMap['_id']}).count() > 0):
                continue
            if (db.ConfidenceDetail.find({"fileNo": sourefileNo, "uid2": entitiesMap['_id']}).count() > 0):
                continue
            if entitiesMap['fileNo'] == "":
                entitiesMap['fileNo'] == "暂无"
            print("开始计算", sourefileNo, entitiesMap['fileNo'])
            db.ConfidenceDetail.remove({"fileNo": sourefileNo, "uid2": entitiesMap['_id']})
            txtFile = entitiesMap['contents']
            # 循环遍历源文件所有的分句
            value = {}
            SourefiletextSum = 0.0
            textSum = 0.0
            for v in range(entities2Count):
                value[entities2[v]['text']] = 0.0
                value['text'] = ""
                q = entities2[v]['text']
                SourefiletextSum += float(len(q))
                for y in txtFile:
                    if len(y) < 4:
                        continue
                    if patterDiqu.search(y) is not None:
                        continue
                    if patterBumen.search(y) is not None:
                        continue
                    if patterYouGuan.search(y) is not None:
                        continue
                    tmp = Likelihood()
                    xhs = tmp.likelihood(q, y)

                    # xhs=pool.apply_async(cal, (q,y,))
                    # pool.close()
                    # pool.join()
                    if xhs is None:
                        xhs = 0.0
                    res = xhs * entities2[v]['weight'] * 1.0
                    # 阈值 float(entities2[v]['threshold']) * 0.01
                    if (res > float(entities2[v]['threshold']) * 0.01):
                        if (res > value[q]):
                            value[q] = res
                            value['text'] = y
                # 相似语句
                sqlres = {
                    "fileNo": sourefileNo,
                    "fileNo2": entitiesMap['fileNo'],
                    "sentence": q,
                    "sentence2": value['text'],
                    "objId": entities2[v]['objId'],
                    "similarity": value[entities2[v]['text']],
                    "threshold": entities2[v]['threshold'],
                    "weight": entities2[v]['weight'],
                    "uid1": entities2[v]['uid'],
                    "uid2": entities[x]['_id'],
                }
                db.ConfidenceDetail.insert_one(sqlres)
                textNum = float(len(entities2[v]['text']) * value[entities2[v]['text']])
                textSum += textNum
            # 相似文件信息,对比完一个文件后计算并存储
            filesimilarity = (textSum / SourefiletextSum) * 100
            # print(filesimilarity)
            fileres = {
                "fileNo": sourefileNo,
                "fileNo2": entitiesMap['fileNo'],
                "filesimilarity": filesimilarity,
                "uid1": entities2[v]['uid'],
                "uid2": entities[x]['_id'],
                "abolitionDate": entities[x]['abolitionDate'],
                "effectiveDate": entities[x]['effectiveDate'],
                "fileName": entities[x]['fileName'],
                "publishDate": entities[x]['publishDate'],
                "publisherCityCode": entities[x]['publisherCityCode'],
                "publisherCityName": entities[x]['publisherCityName'],
                "fileWebsiteUrl": entities[x]['fileWebsiteUrl'],
                "publisher": entities[x]['publisher'],
                "threshold": entities2[v]['threshold'],
            }
            if (db.ConfidenceResult.find({"uid1": entities2[v]['uid'], "uid2": entities[x]['_id']}).count() > 0):
                db.ConfidenceResult.update_one({"uid1": entities2[v]['uid'], "uid2": entities[x]['_id']},
                                               {"$set": fileres})
            else:
                db.ConfidenceResult.insert_one(fileres)
            print(sourefileNo, entitiesMap['fileNo'], "计算完成，存储完毕")
            # 计算结束计时
            time2 = datetime.datetime.today()
            print((time2 - time1).seconds)
    # except Exception:
    #     print("error occur")
    # ______________________________________
    return render_template("admin/bot_cal.html")


@admin.route("/test/")
def test():
    return render_template("admin/test.html")


@admin.route("/test/results/", methods=['GET', "POST"])
def search():
    search_term = request.form["input"]
    # if search_term.find("&"):
    #     res=es.search(index="cmpfile",size=5,body={
    #         "query":{
    #             "bool":{
    #                 "must":[
    #                     {
    #                         "term":{
    #                             search_term
    #                         }
    #                     }
    #                 ]
    #             }
    #         }
    #     })
    res = es.search(index="cmpfile", size=5, body={
        "query": {
            "multi_match": {
                "query": search_term,
                "fields": ["keyword", "fileName", "classfication", "content", "publisher", "publishCityName"],

            },

        },
        "highlight": {
            "pre_tags": ["<em style='color:red'>"],
            "post_tags": ["</em>"],
            "fields": {
                "fileName": {}
            }
        }
    })
    print(res['hits']['hits'][0]['highlight']['fileName'], type(res['hits']['hits'][0]['highlight']['fileName'][0]))
    return render_template("admin/test2.html", res=res)


class Pagination(object):
    """
    自定义分页
    """

    def __init__(self, current_page, total_count, base_url, params, per_page_count=10, max_pager_count=11):
        try:
            current_page = int(current_page)
        except Exception as e:
            current_page = 1
        if current_page <= 0:
            current_page = 1
        self.current_page = current_page
        # 数据总条数
        self.total_count = total_count

        # 每页显示10条数据
        self.per_page_count = per_page_count

        # 页面上应该显示的最大页码
        max_page_num, div = divmod(total_count, per_page_count)
        if div:
            max_page_num += 1
        self.max_page_num = max_page_num

        # 页面上默认显示11个页码（当前页在中间）
        self.max_pager_count = max_pager_count
        self.half_max_pager_count = int((max_pager_count - 1) / 2)

        # URL前缀
        self.base_url = base_url

        # request.GET
        import copy
        params = copy.deepcopy(params)
        # params._mutable = True
        get_dict = params.to_dict()
        # 包含当前列表页面所有的搜/索条件
        # {source:[2,], status:[2], gender:[2],consultant:[1],page:[1]}
        # self.params[page] = 8
        # self.params.urlencode()
        # source=2&status=2&gender=2&consultant=1&page=8
        # href="/hosts/?source=2&status=2&gender=2&consultant=1&page=8"
        # href="%s?%s" %(self.base_url,self.params.urlencode())
        self.params = get_dict

    @property
    def start(self):
        return (self.current_page - 1) * self.per_page_count

    @property
    def end(self):
        return self.current_page * self.per_page_count

    def page_html(self):
        # 如果总页数 <= 11
        if self.max_page_num <= self.max_pager_count:
            pager_start = 1
            pager_end = self.max_page_num
        # 如果总页数 > 11
        else:
            # 如果当前页 <= 5
            if self.current_page <= self.half_max_pager_count:
                pager_start = 1
                pager_end = self.max_pager_count
            else:
                # 当前页 + 5 > 总页码
                if (self.current_page + self.half_max_pager_count) > self.max_page_num:
                    pager_end = self.max_page_num
                    pager_start = self.max_page_num - self.max_pager_count + 1  # 倒这数11个
                else:
                    pager_start = self.current_page - self.half_max_pager_count
                    pager_end = self.current_page + self.half_max_pager_count

        page_html_list = []
        # {source:[2,], status:[2], gender:[2],consultant:[1],page:[1]}
        # 首页
        self.params['page'] = 1
        first_page = '<li><a href="%s?%s">首页</a></li>' % (self.base_url, urlencode(self.params),)
        page_html_list.append(first_page)
        # 上一页
        self.params["page"] = self.current_page - 1
        if self.params["page"] < 1:
            pervious_page = '<li class="disabled"><a href="%s?%s" aria-label="Previous">上一页</span></a></li>' % (
                self.base_url, urlencode(self.params))
        else:
            pervious_page = '<li><a href = "%s?%s" aria-label = "Previous" >上一页</span></a></li>' % (
                self.base_url, urlencode(self.params))
        page_html_list.append(pervious_page)
        # 中间页码
        for i in range(pager_start, pager_end + 1):
            self.params['page'] = i
            if i == self.current_page:
                temp = '<li class="active"><a href="%s?%s">%s</a></li>' % (self.base_url, urlencode(self.params), i,)
            else:
                temp = '<li><a href="%s?%s">%s</a></li>' % (self.base_url, urlencode(self.params), i,)
            page_html_list.append(temp)

        # 下一页
        self.params["page"] = self.current_page + 1
        if self.params["page"] > self.max_page_num:
            self.params["page"] = self.current_page
            next_page = '<li class="disabled"><a href = "%s?%s" aria-label = "Next">下一页</span></a></li >' % (
                self.base_url, urlencode(self.params))
        else:
            next_page = '<li><a href = "%s?%s" aria-label = "Next">下一页</span></a></li>' % (
                self.base_url, urlencode(self.params))
        page_html_list.append(next_page)

        # 尾页
        self.params['page'] = self.max_page_num
        last_page = '<li><a href="%s?%s">尾页</a></li>' % (self.base_url, urlencode(self.params),)
        page_html_list.append(last_page)

        return ''.join(page_html_list)


def cal(strx, stry):
    return Likelihood().likelihood(strx, stry)
