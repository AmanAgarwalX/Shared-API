from Shared import db, login_manager
from flask_login import UserMixin, current_user
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


groups_table = db.Table('groups', db.Column('user_id',
                                            db.String(120), db.ForeignKey('user.id')),
                        db.Column('group_id', db.Integer, db.ForeignKey('group.id')))


class User(db.Model, UserMixin):
    id = db.Column(db.String(120), primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    sharing_with = db.Column(db.String(120))
    latitude = db.Column(db.String(120))
    longitude = db.Column(db.String(120))
    last_seen = db.Column(db.String(120))
    token = db.Column(db.String(120))
    user_id = db.Column(db.String(120))
    profile_picture = db.Column(
        db.String(50), nullable=False, default='default.jpg')
    password = db.Column(db.String(12), nullable=False)
    groups_created = db.relationship('Group', backref='admin_ref', lazy=True)
    shared_pics = db.relationship(
        'SharedPics', backref='sharer_ref', lazy=True)
    groups = db.relationship(
        'Group', secondary=groups_table, backref=db.backref('members', lazy=True))

    def __repr__(self):
        return f"User('{self.id}','{self.name}','{self.email}','{self.profile_picture}')"


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin = db.Column(db.String(120), db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    shared_pics = db.relationship('SharedPics', backref='group_ref', lazy=True)

    def __repr__(self):
        return f"Group('{self.id}','{self.name}','{self.admin}')"


class SharedPics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    picture = db.Column(db.String(50), nullable=False)
    thumb = db.Column(db.String(50), nullable=False)
    group = db.Column(db.String(120), db.ForeignKey(
        'group.id'), nullable=False)
    sharer = db.Column(db.String(120), db.ForeignKey(
        'user.id'), nullable=False)

    def __repr__(self):
        return f"Pic('{self.id}','{self.picture}','{self.thumb}')"
