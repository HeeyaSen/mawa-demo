from datetime import datetime
from hashlib import md5
from app import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from time import time
import jwt
from app import app 
import pandas as pd 
import sqlite3
import re

followers = db.Table(
	'followers',
	db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
	db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), index=True, unique=True)
	email = db.Column(db.String(120), index=True, unique=True)
	password_hash = db.Column(db.String(128))
	posts = db.relationship('Post', backref='author', lazy='dynamic')
	about_me = db.Column(db.String(140))
	last_seen = db.Column(db.DateTime, default=datetime.utcnow)
	followed = db.relationship(
		'User', secondary=followers,
		primaryjoin=(followers.c.follower_id == id),
		secondaryjoin=(followers.c.followed_id == id),
		backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

	def __repr__(self):
		return '<User {}>'.format(self.username)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

	def avatar(self, size):
		digest = md5(self.email.lower().encode('utf-8')).hexdigest()
		return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
			digest, size)

	def follow(self, user):
		if not self.is_following(user):
			self.followed.append(user)

	def unfollow(self, user):
		if self.is_following(user):
			self.followed.remove(user)

	def is_following(self, user):
		return self.followed.filter(
			followers.c.followed_id == user.id).count() > 0

	def followed_posts(self):
		followed = Post.query.join(
			followers, (followers.c.followed_id == Post.user_id)).filter(
				followers.c.follower_id == self.id)
		own = Post.query.filter_by(user_id=self.id)
		return followed.union(own).order_by(Post.timestamp.desc())

	def get_reset_password_token(self, expires_in=600):
		return jwt.encode(
			{'reset_password': self.id, 'exp': time() + expires_in},
			app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

	@staticmethod
	def verify_reset_password_token(token):
		try:
			id = jwt.decode(token, app.config['SECRET_KEY'],
							algorithms=['HS256'])['reset_password']
		except:
			return
		return User.query.get(id)


@login.user_loader
def load_user(id):
	return User.query.get(int(id))


class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	tent = db.Column(db.String(140))
	prefab = db.Column(db.String(140))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	order = db.Column(db.String(140))

	###
	prefab_val = 10 #people
	kit_val = 15 #people
	tent_val = 5 #people
	order_time = 1 #months
	tent_lifetime = 6 #months
	prefab_lifetime = 12 #months
#
	def pop_timeline(x, y, tent_val, prefab_val, order_time, tent_lifetime, prefab_lifetime):
	#let tents, prefab be lists of tuples of the form (amount, age)
	#create a dictionary whose keys are quantities of people and values are when they need housing
		x = str(x)
		y = str(y)
		breakdownx = re.findall('\(.*?,.*?\)', x)
		tents = []
		for i in breakdownx:
			tents.append(tuple([x for x in i[1:-1].split(',')]))

		breakdowny = re.findall('\(.*?,.*?\)', y)
		prefab = []
		for i in breakdowny:
			prefab.append(tuple([x for x in i[1:-1].split(',')]))
		#print(tents)
		#print(prefab)
		tent_remainder = []
		prefab_remainder = []
		orders = dict()
		for (x,y) in tents:
			x = int(x)
			y = int(y)
			tent_remainder.append((x, tent_lifetime - y))
		for (x,y) in prefab:
			x = int(x)
			y = int(y)
			prefab_remainder.append((x, prefab_lifetime - y))
		#(x = # tents,y = when they will run out)
		#print(tent_remainder)
		#print(prefab_remainder)
		for (x,y) in tent_remainder:
			if y <= order_time:
				orders[0] = orders.get(0, 0)+(5*x)
			else:
				orders[y-order_time] = orders.get(y-order_time, 0)+(5*x)
		for (x,y) in prefab_remainder:
			if y <= order_time:
				 orders[0] = orders.get(0, 0)+(10*x)
			else:
				orders[y-order_time] = orders.get(y-order_time,0)+(10*x)
		#(when they need housing, for how many people)
		print(orders)
		for (x,y) in orders.items():
			y=(y-(y%15)+15)/15
		return orders
	#order = str(pop_timeline(tent, prefab, tent_val, prefab_val, order_time, tent_lifetime, prefab_lifetime))
	print(order)
	def __repr__(self):
		return '<Post {} {} {}>'.format(self.tent, self.prefab, self.order)