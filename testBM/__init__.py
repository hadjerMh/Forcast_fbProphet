from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = '3ba19caeb1cf12aa656210175468c335'
# database
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///site.sqlite3"
db = SQLAlchemy(app)
# Migrating the db
migrate = Migrate(app, db)
# hashing
bcrypt = Bcrypt(app)
# Login manger
loginManager = LoginManager(app)
# Specify a path when login is required
loginManager.login_view = 'login'

from testBM import routes
