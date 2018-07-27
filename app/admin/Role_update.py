from pymongo import MongoClient
from werkzeug.security import generate_password_hash
import datetime, re, json
from elasticsearch import Elasticsearch
from bson.objectid import ObjectId
from flask import current_app

from config import DevelopmentConfig

es = Elasticsearch("http://127.0.0.1:9200/")
condev = DevelopmentConfig()
mongoIP = condev.MONGOIP
mongoPort = condev.MONGOPORT
db = MongoClient(mongoIP, port=mongoPort)
db = db.FireFly2
for v in range(1, 2):
    admin1 = {
        'username': 'admin' + str(v),
        'email': '2148084512@qq.com',
        'activate': True,
        'password': generate_password_hash('123456' + str(v - 1)),
        'is_super': 0,
        'name': 'Cin',
        'role_id': 1,
        'addtime': datetime.datetime.utcnow()
    }
    # db.Admin.insert(admin1)

for v in range(1, 100):
    tag = {
        'name': '经济' + str(v),
        'addtime': datetime.datetime.utcnow()
    }
    # db.Tag.insert_one(tag)

content = {
    'indexNum': '000014349/2017-00156',
    'fileType': '商贸、海关、旅游\对外经贸合作',
    'publisher': '国务院',
    'createTime': '2017年08月08日',
    'title': '国务院关于促进外资增长若干措施的通知',
    'fileNo': '国发〔2017〕39号',
    'PublishDate': '2017年08月16日',
    'addtime': datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    'path': '/',
    'tag': '对外开放',
    'url': 'http://www.gov.cn/zhengce/content/2017-08/16/content_5218057.htm'
}
# db.SoureFile.insert_one(content)
admin1 = {
    'username': 'admin',
    'email': '2148084512@qq.com',
    'activate': True,
    'password': generate_password_hash('1'),
    'is_super': 0,
    'name': 'Cin',
    'role_id': 1,
    'addtime': datetime.datetime.utcnow()
}
# db.Admin.insert_one(admin1)

sourefile = db.SoureFile.find_one({"fileNo": "国发〔2017〕5号"})
# 分句
# print(sourefile)
# content=sourefile['content']
# content=content.strip()
# content=content.replace(" ","")
# patterQiantou=re.compile(r'(().*?牵头.*?())')
# patterFuze=re.compile(r'(().*?负责.*?())')
# patterGuofa=re.compile(r'(().*?国发.*?())')
# strSub=re.split(r"。|；|;|）|（|:|：",content)
# xxx=[]
# if strSub is not  None:
#     for x in strSub:
#         x="".join(x.split())
#         if len(x)>3 and x!="":
#             if patterFuze.search(x) is not None:
#                 continue
#             if patterQiantou.search(x) is not None:
#                 continue
#             if patterGuofa.search(x) is not None:
#                 continue
#             xxx.append(x)
#
#
# for v in xxx:
# print(xxx.index(v),v)

# print(db.CmpFile.find({'publisherCityName': re.compile('南京')}).count())


data = db.CmpFile.find({}).limit(1500)
for v in data:
    # es = Elasticsearch("http://127.0.0.1:9200/")
    esdata = json.dumps(
        {
            "uid": str(v['_id']),
            'classfication': v['classfication'],
            'content': v['content'],
            'fileName': v['fileName'],
            'fileNo': v['fileNo'],
            'indexNum': v['indexNum'],
            'keyword': v['keyword'],
            'publisher': v['publisher'],
            'publishCityName': v['publisherCityName'],
        }
    )
    # espost = es.index(index="cmpfile", doc_type="file", body=esdata)

# search_term="外资"
# res = es.search(index="cmpfile", size=20, body={
#     "query": {
#         "multi_match": {
#             "query": search_term, "fields": ["keyword", "fileName", "classfication", "content","publisher","publishCityName"]
#         }
#     }
# })
# print(res)
# cmpcontent = db.ConfidenceResult.find()
# for v in cmpcontent:
#     cmpfile = db.CmpFile.find_one({"_id": ObjectId(v['uid2'])})
#     db.ConfidenceResult.update(v, {"$set": {"content": cmpfile['content']}})
