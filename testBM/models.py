from testBM import db, loginManager
from flask_login import UserMixin

@loginManager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    files = db.relationship('File', backref='userFile', lazy=True)

    def __repr__(self):
        return f"User('{self.id}', '{self.username}','{self.email}')"


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    originalFileName = db.Column("fileName", db.String(100))
    estimatedFileName = db.Column("fileNameEstimation", db.String(100))
    fig1Name = db.Column(db.String(100))
    fig2Name = db.Column(db.String(100))
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"User('{self.id}', '{self.originalFileName}')"