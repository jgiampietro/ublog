import os
import webapp2
import jinja2
import hashlib
import hmac
from string import letters
import random
import re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = "007JamesBondStyleHashWhoa007"

def make_salt():
	return ''.join(random.choice(letters) for x in range(5))

def make_pw(username, password, salt = None):
	if not salt:
		salt = make_salt()

	secure_pw = hashlib.sha256(username + password + salt).hexdigest()
	return  "%s|%s" % (salt, secure_pw)

def check_pw(username, password, secure_pw):
	salt = secure_pw.split('|')[0]
	return make_pw(username, password, salt) == secure_pw

def make_secure_cookie(user_id):
	secure_id = hmac.new(secret, user_id).hexdigest()
	return "%s|%s" % (user_id, secure_id)

def check_cookie(cookie):
	user_id = cookie.split('|')[0]
	return make_secure_cookie(user_id) == cookie


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def make_cookie(self, user_id):
		cookie = make_secure_cookie(user_id)
		self.response.headers.add_header(
			'Set-Cookie', "user_id=%s; Path=/" % (cookie))

	def read_cookie(self):
		cookie = self.request.cookies.get('user_id')
		return check_cookie(cookie)

	def return_id_by_cookie(self):
		users_cookie = self.request.cookies.get('user_id')
		user_id = users_cookie.split('|')[0]
		return int(user_id)

	def login(self, user_db_entry):
		cookie = self.make_cookie(str(user_db_entry.key().id()))

	def logout(self):
		self.response.headers.add_header(
			'Set-Cookie', 'user_id=; Path=/')



class HomePage(Handler):
	def get(self):
		self.render('homepage.html')

class users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	is_admin = db.BooleanProperty()
	join_date = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def signup(cls, username, password, email=None):
		secure_pw = make_pw(username, password)
		return users(username=username,
					 password=secure_pw,
					 email=email)

	@classmethod
	def find_by_un(cls, username):
		c = users.all()
		d = c.filter('username =', username).get()
		return d

	@classmethod
	def return_key(cls, user_entity):
		key = db.Key.from_path('users', int(user_entity))
		c = db.get(key)
		return c


class blogposts(db.Model):
	title = db.StringProperty(required = True)
	body = db.TextProperty(required = True)
	create_date = db.DateTimeProperty(auto_now_add = True)
	likes = db.IntegerProperty()
	dislikes = db.IntegerProperty()

class comments(db.Model):
	create_user = db.StringProperty(required = True)
	create_time = db.DateTimeProperty(auto_now_add = True)
	content = db.TextProperty(required = True)


def valid_username(username):
    username_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and username_RE.match(username)

def valid_password(password):
    password_RE = re.compile(r"^.{3,20}$")
    return password and password_RE.match(password)

def valid_email(email):
    email_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or email_RE.match(email)

class SignUp(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")
		error=False

		params=dict(username=self.username, email=self.email)

		if not valid_username(self.username):
			params['username_error'] = "Invalid Username"
			error = True

		if not valid_password(self.password):
			params['password_error'] = "Invalid Password"
			error = True

		if self.password != self.verify:
			params['verify_error'] = "Passwords do not match"
			error = True

		if not valid_email(self.email):
			params['email_error'] = "Invalid Email Address"
			error = True

		if users.find_by_un(self.username):
			params['dupe_error'] = "Username already exists"
			error = True

		if error:
			self.render("signup.html", **params)

		else:
			c = users.signup(self.username, self.password, self.email)
			c.put()
			self.login(c)
			self.redirect('/blog/welcomepage')


class LogIn(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		self.username = self.request.get("username")
		self.password = self.request.get("password")

		c = users.find_by_un(self.username)

		params = dict()

		if c.username:
			if check_pw(self.username, self.password, c.password):
				self.login(c)
				self.redirect('/blog/welcomepage')
			else:
				params['error_username'] = "Invalid username/password combination"
				self.render("login.html", **params)
		else:
			params['error_password'] = "No such user exists"
			self.render("login.html", **params)

class WelcomePage(Handler):
	def get(self):
		user_id = self.return_id_by_cookie()
		if user_id:
			key = db.Key.from_path('users', user_id)
			user_entity = db.get(key)
			name = user_entity.username
			self.render("welcomepage.html", name=name)
		else:
			self.redirect("/blog/login")

class AdminPage(Handler):
	def get(self):
		if self.read_cookie():
			c = db.GqlQuery("SELECT * from users")
			self.render("adminpage.html", users=c)
		else:
			error = "You must logged in to view this page!"
			self.render("adminpage.html", error=error)

class DeleteUser(Handler):
	def get(self, user_id):
		key = db.Key.from_path('users', int(user_id))
		c = db.get(key)
		c.delete()
		d = db.GqlQuery("SELECT * FROM users")

		self.render("adminpage.html", users=d )

class DeleteAllPosts(Handler):
	def get(self):
		for i in blogposts.all():
			db.delete(i)
		self.redirect('/')

class LogOut(Handler):
	def get(self):
		self.logout()
		self.redirect('/')




app = webapp2.WSGIApplication([('/', HomePage),
							   ('/blog/signup', SignUp),
							   ('/blog/login', LogIn),
							   ('/blog/welcomepage', WelcomePage),
							   ('/blog/adminpage', AdminPage),
							   ('/blog/deleteuser/(\d+)', DeleteUser),
							   ('/blog/deleteallposts', DeleteAllPosts),
							   ('/blog/logout', LogOut)],
								debug=True)