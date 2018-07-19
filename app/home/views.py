from . import home
from flask import render_template, redirect, url_for, flash, session, request, current_app
from .forms import LoginForm, IndexForm, DbwjForm, XzqhForm
# , TagForm, SoureFileForm, CmpFileForm
from pymongo import MongoClient, DESCENDING
from ..models import verify_password
from flask_login import login_user, logout_user, login_required, current_user
import os, datetime, uuid
from urllib.parse import urlencode, quote, unquote
from bson.objectid import ObjectId
from functools import wraps
import re
from bson import json_util as jsonb
from config import DevelopmentConfig

condev = DevelopmentConfig()
mongoIP = condev.MONGOIP
mongoPort = condev.MONGOPORT
db = MongoClient(mongoIP, port=mongoPort)
db = db.FireFly2


@home.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


# 登陆装饰器
def home_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@home.route('/index/', methods=['GET', 'POST'])
@home_login_req
def index():
    # 获取文号
    sourcefile = db.SoureFile.find({}, {"_id": 1, "fileNo": 1})
    # print(choices)
    form = IndexForm()
    if form.validate_on_submit():
        print("index_smt")
        data = form.data
        return redirect(url_for('home.dbwj_f', Num=request.form.get("Num"), keyWord=data["keyWord"], page=1))
    return render_template('home/index.html', form=form, choices=sourcefile)


@home.route('/')
def trans():
    return redirect(url_for('home.login'))


@home.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = db.Admin.find_one({"username": data['account']})
        print(user)
        if user is not None and verify_password(user.get('password'), data['pwd']):
            session['user'] = data['account']
            return redirect(url_for('home.index'))
        elif not verify_password(user.get('password'), data['pwd']):
            flash("密码错误!", 'err')
            return redirect(url_for('home.login'))
    return render_template('home/login.html', form=form)


@home.route('/logout/')
def logout():
    session.pop('user', None)
    session.clear()
    return redirect(url_for('home.login'))


@home.route('/pwd/', methods=['GET', 'POST'])
@home_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        # 建议将用户表重新命名 -20180706lht
        user = db.Admin.find_one({'username': session['user']})
        from werkzeug.security import generate_password_hash
        newadmin = user
        newpwd = generate_password_hash(data['new_pwd'])
        db.Admin.update(user, {'$set': {'password': newpwd}})
        flash("密码修改成功", 'ok')
        redirect(request.args.get('next') or url_for('home.logout'))
    return render_template('home/pwd.html', form=form)


@home.route('/dbwj_f/<int:page>', methods=['GET', 'POST'])
@home_login_req
def dbwj_f(page=None):
    print("dbwj_f")
    # 处理提交事件
    form = DbwjForm()
    if form.validate_on_submit():
        print("dbwj_f_smt")
        data = form.data
        return redirect(url_for('home.dbwj_s', Num=request.args.get("Num"), keyWord=data["keyWord"], page=1))
    # 公告信息
    noticel = []
    tempn = db.Notice.find({"activation": "是"}, {"content": 1}).sort('addtime', -1)
    for n in tempn:
        noticel.append(n)
        break
    notice = noticel[0]["content"]
    # print(notice)
    # 国发文内容
    # print(request.args.get("Num"))
    doc = db.SoureFile.find_one({"_id": ObjectId(request.args.get("Num"))})
    # 添加全文检索
    if page == None:
        page = 1
    # 第一次检索结果
    res = db.ConfidenceResult.find({"uid1": ObjectId(request.args.get("Num")), "filesimilarity": {'$gt': 0}}).sort(
        "filesimilarity", -1)
    # print(jsonb.dumps(res))
    results = []
    for r in res:
        # print(r.get("uid2"))
        t = db.CmpFile.find_one({"_id": ObjectId(r["uid2"]), "content": re.compile(request.args.get("keyWord"))})
        if t:
            t["filesimilarity"] = r.get("filesimilarity")
            results.append(t)
    count = len(results)
    print("dbwj一次检索结果数")
    print(count)
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args, per_page_count=8)
    html = paper_obj.page_html()
    param = []
    # 清空临时库
    db.CmpTemp.remove({})
    for v in range(count):
        db.CmpTemp.insert(results[v])
        param.append([v + 1, results[v].get("fileName"), results[v].get("fileNo"), results[v].get("publisherCityName"),
                      results[v].get("publisher"), results[v].get("publishDate"), results[v].get("_id"),
                      results[v].get("filesimilarity"), results[v].get("fileWebsiteUrl")])
    index_list = param[paper_obj.start:paper_obj.end]
    return render_template('home/dbwj.html', form=form, Notice=notice, doc=doc, html=html, index_list=index_list)


@home.route('/dbwj_s/<int:page>', methods=['GET', 'POST'])
@home_login_req
def dbwj_s(page=None):
    print("dbwj_s")
    # 处理提交事件
    form = DbwjForm()
    if form.validate_on_submit():
        print("dbwj_s_smt")
        data = form.data
        return redirect(url_for('home.dbwj_s', Num=request.args.get("Num"), keyWord=data["keyWord"], page=1))
    # 公告信息
    noticel = []
    tempn = db.Notice.find({"activation": "是"}, {"content": 1}).sort('addtime', -1)
    for n in tempn:
        noticel.append(n)
        break
    notice = noticel[0]["content"]
    print("公告" + notice)
    # 国发文内容
    # print(request.args.get("Num"))
    doc = db.SoureFile.find_one({"_id": ObjectId(request.args.get("Num"))})
    # 添加全文检索
    if page == None:
        page = 1
    # 第二次检索结果
    result = db.CmpTemp.find({'$or': [{"fileName": re.compile(request.args.get("keyWord"))},
                                      {"content": re.compile(request.args.get("keyWord"))}]})
    count = result.count()
    results = []
    for r in result:
        results.append(r)
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args, per_page_count=8)
    html = paper_obj.page_html()
    param = []
    # 清空临时库
    db.CmpTemp.remove({})
    for v in range(count):
        # 保存查询结果到临时库
        db.CmpTemp.insert(results[v])
        param.append([v + 1, results[v].get("fileName"), results[v].get("fileNo"), results[v].get("publisherCityName"),
                      results[v].get("publisher"), results[v].get("publishDate"), results[v].get("_id"),
                      results[v].get("filesimilarity")])
    index_list = param[paper_obj.start:paper_obj.end]
    return render_template('home/dbwj.html', form=form, Notice=notice, doc=doc, html=html, index_list=index_list)


@home.route('/dbwj_detail/', methods=['GET', 'POST'])
@home_login_req
def dbwj_detail():
    # get方法获取参数
    # name = request.args.get("name")
    # post方法获取参数
    # name = request.form.get("name")
    sourceid = request.form.get("sourceid")
    print("国发文件id" + sourceid)
    cmpid = request.form.get("cmpid")
    print("对比文件id" + cmpid)
    # 国发文
    sourcefile = db.SoureFile.find_one({"_id": ObjectId(sourceid)}, {"content": 0})
    # print(sourcefile)
    # 对比文 基础信息
    cmpfile = db.CmpFile.find_one({"_id": ObjectId(cmpid)}, {"content": 0, "contents": 0})
    # 对比文 对比结果集
    cmpresult = db.ConfidenceDetail.find({"uid1": ObjectId(sourceid), "uid2": ObjectId(cmpid)}).sort(
        "objId")
    cmpResult = []
    if cmpresult:
        cmpResCount = cmpresult.count()
        for r in cmpresult:
            cmpResult.append(r)
    else:
        cmpResCount = 0
    print("对比结果集")
    # print(jsonb.dumps(cmpresult))
    # cmpfile["resultResult"] = cmpresult
    # 对比相似度
    cmpsim = db.ConfidenceResult.find_one({"uid1": ObjectId(sourceid), "uid2": ObjectId(cmpid)})
    if cmpsim:
        cmpsim = cmpsim.get("filesimilarity")
    else:
        cmpsim = 0
    print("对比相似度")
    print(cmpsim)
    result = {
        "cmpSim": cmpsim,
        "resultCount": cmpResCount,
        "cmpfile": cmpfile,
        "sourcefile": sourcefile,
        "cmpResult": jsonb.dumps(cmpResult)
    }
    print("对比结果")
    print(result)
    # 将dict转换成json
    result = jsonb.dumps(result)
    return result


@home.route('/xzqh_f/<int:page>', methods=['GET', 'POST'])
@home_login_req
def xzqh_f(page=None):
    areaId = request.args.get("areaId")
    keyWord = request.args.get("keyWord")
    print("xzqh_f")
    form = XzqhForm()
    if form.validate_on_submit():
        print("xzqh_f_smt")
        data = form.data
        return redirect(url_for('home.xzqh_s', keyWord=data["keyWord"], page=1, areaId=request.args.get("areaId")))
    # 获取行政区划
    arealist = db.AreaList.find()
    arealist_count = arealist.count()
    print("省数量")
    print(arealist_count)
    # 获取数据
    if page == None:
        page = 1

    if keyWord and areaId:
        results = db.CmpFile.find({"publisherCityCode": areaId},
                                  {'$or': [{"fileName": re.compile(keyWord)}, {"content": re.compile(keyWord)}]}).sort(
            "_id")
        print("a")
    elif request.args.get("areaId"):
        results = db.CmpFile.find({"publisherCityCode": areaId}).sort("_id")
        print("b")
    else:
        print("c")
        results = None
    if results:
        count = results.count()
    else:
        count = 0
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args, per_page_count=5)
    html = paper_obj.page_html()
    param = []
    for v in range(count):
        param.append([v + 1, results[v].get("fileName"), results[v].get("fileNo"), results[v].get("publisherCityName"),
                      results[v].get("publisher"), results[v].get("publishDate"), results[v].get("_id")])
    index_list = param[paper_obj.start:paper_obj.end]
    #  , form = form, Notice = notice, Area = area, html = html, index_list = index_list#
    return render_template('home/xzqh.html', areaId=areaId, form=form, arealist=arealist, arealist_count=arealist_count,
                           index_list=index_list, html=html)


@home.route('/xzqh_s/<int:page>', methods=['GET', 'POST'])
@home_login_req
def xzqh_s(page=None):
    areaId = request.args.get("areaId")
    print("xzqh_s")
    form = XzqhForm()
    if form.validate_on_submit():
        print("xzqh_s_smt")
        data = form.data
        return redirect(url_for('home.xzqh_s', keyWord=data["keyWord"], page=1, areaId=request.args.get("areaId")))
    # 获取行政区划
    arealist = db.AreaList.find()
    arealist_count = arealist.count()
    print("省数量")
    print(arealist_count)
    # 获取数据
    if page == None:
        page = 1
    if request.args.get("keyWord") or request.args.get("areaId"):
        results = db.CmpFile.find({"publisherCityCode": request.args.get("areaId")}, {'$or': [
            {"fileName": re.compile(request.args.get("keyWord")),
             "content": re.compile(request.args.get("keyWord"))}]}).sort("_id")
    else:
        results = None
    if results:
        count = results.count()
    else:
        count = 0
    paper_obj = Pagination(request.args.get("page", page), count, request.path, request.args, per_page_count=5)
    html = paper_obj.page_html()
    param = []
    for v in range(count):
        param.append([v + 1, results[v].get("fileName"), results[v].get("fileNo"), results[v].get("publisherCityName"),
                      results[v].get("publisher"), results[v].get("publishDate"), results[v].get("_id")])
    index_list = param[paper_obj.start:paper_obj.end]
    #  , form = form, Notice = notice, Area = area, html = html, index_list = index_list#
    return render_template('home/xzqh.html', areaId=areaId, form=form, arealist=arealist, arealist_count=arealist_count,
                           index_list=index_list, html=html)


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
