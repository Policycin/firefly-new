# coding:utf8

from app import app
from flask_script import Manager

manage = Manager(app)
if __name__ == "__main__":
    # manage.run()
    app.run(
    # WSGIServer(('0.0.0.0',5003),app).serve_forever()
        host='0.0.0.0',
        port=5003,
        debug=True
    )
