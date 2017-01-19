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
		if cookie:
			return check_cookie(cookie)

	def return_id_by_cookie(self):
		users_cookie = self.request.cookies.get('user_id')
		if users_cookie:
			user_id = users_cookie.split('|')[0]
			return int(user_id)

	def login(self, user_db_entry):
		cookie = self.make_cookie(str(user_db_entry.key().id()))

	def logout(self):
		self.response.headers.add_header(
			'Set-Cookie', 'user_id=; Path=/')

	def replace(self, body):
		content = body.replace('\n', '<br>')
		return content



class HomePage(Handler):
	def get(self):
		self.render('homepage.html')

class users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	is_admin = db.BooleanProperty()
	join_date = db.DateTimeProperty(auto_now_add = True)
	liked_posts = db.StringListProperty()

	@classmethod
	def signup(cls, username, password, email=None):
		secure_pw = make_pw(username, password)
		return users(username=username,
					 password=secure_pw,
					 email=email)

	@classmethod
	def find_by_id(cls, user_id):
		key = db.Key.from_path('users', int(user_id))
		c = db.get(key)
		return c

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
	create_user = db.StringProperty(required = True)
	like_users = db.StringListProperty()

	def replace(self, text):
		content = text.replace('\n', '<br>')
		return content

	@classmethod
	def post(cls, title, body, create_user):
		return blogposts(title=title,
						 body=body,
						 create_user=create_user,
						 likes=0)

	@classmethod
	def return_key(cls, post_key):
		key = db.Key.from_path('blogposts', int(post_key))
		c = db.get(key)
		return c

	@classmethod
	def post_by_id(cls, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		c = db.get(key)
		return c

class comments(db.Model):
	create_user = db.StringProperty(required = True)
	title = db.StringProperty(required = True)
	body = db.TextProperty(required = True)
	create_date = db.DateTimeProperty(auto_now_add = True)
	post = db.StringProperty(required = True)

	@classmethod
	def post_comment(cls, create_user, title, body, post):
		return comments(create_user=create_user,
						title=title,
						body=body,
						post=post)

	@classmethod
	def comments_by_post_id(cls, post_id):
		c = comments.all()
		d = c.filter('post =', post_id)
		return d

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
		error_password=""
		error_username=""

		c = users.find_by_un(self.username)

		params = dict()
		if c:
			if check_pw(self.username, self.password, c.password):
				self.login(c)
				self.redirect('/blog/welcomepage')
			else:
				error_password = "Invalid username/password combination"
				self.render("login.html", error_password=error_password)
		else:
			error_username = "No such username exists"
			self.render("login.html", error_username=error_username)

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
		self.redirect('/blog/signup')

class NewPost(Handler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		params = dict()

		if self.read_cookie():
			self.title = self.request.get("title")
			self.body = self.request.get("body")
			self.create_user = users.find_by_id(self.return_id_by_cookie())
			error = False

			if not self.title:
				params['title_error'] = "You must enter a title"
				error = True

			if not self.body:
				params['body_error'] = "You must enter a body"
				error = True

			if error:
				params['title'] = self.title
				params['body'] = body
				self.render("newpost.html", **params)

			else:
				c = blogposts.post(self.title, self.body, self.create_user.username)
				c.put()
				post_id = c.key().id()
				self.redirect('/blog/postpage/%s' % post_id)
		else:
			params['login_error'] = "You must be logged in to post!"
			self.render("newpost.html", **params)

class PostPage(Handler):
	def get(self, post_id):
		post = blogposts.post_by_id(post_id)
		self.user = ""
		post_comments = comments.comments_by_post_id(str(post_id))
		if self.read_cookie():
			self.user = users.find_by_id(self.return_id_by_cookie())
		self.render("postpage.html", post=post, user=self.user, comments=post_comments)

class MainPage(Handler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM blogposts order by create_date desc limit 10")
		current_user = ""

		if self.return_id_by_cookie():
			current_user = users.find_by_id(self.return_id_by_cookie())

		self.render("mainpage.html", posts=posts, current_user=current_user)

class LikePost(Handler):
	def get(self, post_id):
		if self.read_cookie():
			self.like_user = users.find_by_id(self.return_id_by_cookie())
			key = db.Key.from_path('blogposts', int(post_id))
			post = db.get(key)
			if self.like_user.username != post.create_user:
				check_history = post.like_users
				if self.like_user.username not in check_history:
					post.likes = post.likes + 1
					post.like_users.append(self.like_user.username)
					post.put()
					self.like_user.liked_posts.append(str(post.key().id()))
					self.redirect('/blog')
				else:
					self.write("You cannot like a post more than once!")
			else:
				self.write("You cannot like your own post")
		else:
			self.write("You must be logged in to like a post")

class MyPosts(Handler):
	def get(self):
		if self.read_cookie():
			self.like_user = users.find_by_id(self.return_id_by_cookie())
			c = blogposts.all().filter('create_user =', self.like_user.username)
			self.render("myposts.html", posts=c)
		else:
			self.redirect('/blog/login')

class EditPost(Handler):
	def get(self, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		post = db.get(key)
		self.render('editpost.html', post=post)

	def post(self, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		post = db.get(key)
		self.title = self.request.get("title")
		self.body = self.request.get("body")
		body = self.body.replace('\n', '<br>')

		post.title = self.title
		post.body = self.body
		post.put()
		self.redirect('/blog/postpage/%s' % str(post.key().id()))

class DeletePost(Handler):
	def get(self, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		post = db.get(key)
		post.delete()
		self.redirect('/blog/myposts')

class Comment(Handler):
	def get(self, post_id):
		post = blogposts.post_by_id(post_id)
		self.render('comment.html', post=post)
	def post(self, post_id):
		if self.read_cookie():
			self.comment_user = users.find_by_id(self.return_id_by_cookie())
			self.title = self.request.get("title")
			self.body = self.request.get("body")
			self.post = post_id
			error = False
			error_title = ""
			error_body = ""

			if not self.title:
				error_title = "Please enter a title"
				error = True
			if not self.body:
				error_body = "Please enter a body"
				error = True

			if not error:
				c = comments.post_comment(self.comment_user.username, self.title,
										  self.body, self.post)
				c.put()
				self.redirect('/blog/postpage/%s' % self.post)
			else:
				self.render('comment.html', post=self.post, error_title=error_title,
											error_body=error_body, title=self.title,
											body=self.body)
		else:
			self.redirect('/blog/login')

class ViewComment(Handler):
	def get(self, comment_id):
		key = db.Key.from_path('comments', int(comment_id))
		comment = db.get(key)
		self.render("viewcomment.html", comment=comment)




app = webapp2.WSGIApplication([('/', HomePage),
							   ('/blog', MainPage),
							   ('/blog/signup', SignUp),
							   ('/blog/login', LogIn),
							   ('/blog/welcomepage', WelcomePage),
							   ('/blog/adminpage', AdminPage),
							   ('/blog/deleteuser/(\d+)', DeleteUser),
							   ('/blog/deleteallposts', DeleteAllPosts),
							   ('/blog/postpage/(\d+)', PostPage),
							   ('/blog/newpost', NewPost),
							   ('/blog/likepost/(\d+)', LikePost),
							   ('/blog/editpost/(\d+)', EditPost),
							   ('/blog/deletepost/(\d+)', DeletePost),
							   ('/blog/comment/(\d+)', Comment),
							   ('/blog/viewcomment/(\d+)', ViewComment),
							   ('/blog/myposts', MyPosts),
							   ('/blog/logout', LogOut)],
								debug=True)