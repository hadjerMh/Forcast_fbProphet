from testBM import db, loginManager
from flask_login import UserMixin


# Creating a user_load callback in order to reload the user object from the user ID stored in the session
@loginManager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """
    Class model for the user creation inherit from db.Model for the database creation and UserMixin
    for the user authentication
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    files = db.relationship('File', backref='userFile', lazy=True)

    def __repr__(self):
        return f"User('{self.id}', '{self.username}','{self.email}')"


class File(db.Model):
    """
    Class Model for files association with th inserted file and the estimated files,
    it takes in some variables (daily, weekly and yearly) that contributes for model training.
    """
    id = db.Column(db.Integer, primary_key=True)
    originalFileName = db.Column("fileName", db.String(100))
    estimatedFileName = db.Column("fileNameEstimation", db.String(100))
    daily = db.Column(db.Boolean, default=False)
    weekly = db.Column(db.Boolean, default=False)
    yearly = db.Column(db.Boolean, default=False)
    period = db.Column(db.Integer)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"User('{self.id}', '{self.originalFileName}')"
