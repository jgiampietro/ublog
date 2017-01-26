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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "007JamesBondStyleHashWhoa007"

# some global functions for securing passwords and cookies


def make_salt():
    return ''.join(random.choice(letters) for x in range(5))


def make_pw(username, password, salt=None):
    """Takes in a username and password, outputs
    a secure password for database storage"""
    if not salt:
        salt = make_salt()
    secure_pw = hashlib.sha256(username + password + salt).hexdigest()
    return  "%s|%s" % (salt, secure_pw)


def check_pw(username, password, secure_pw):
    """Checks username and password against stored
    password value"""
    salt = secure_pw.split('|')[0]
    return make_pw(username, password, salt) == secure_pw


def make_secure_cookie(user_id):
    """Takes users datastore key and creates
    an encrypted cookie for login persistence"""
    secure_id = hmac.new(secret, user_id).hexdigest()
    return "%s|%s" % (user_id, secure_id)


def check_cookie(cookie):
    """pass in the users cookie, returns True/False
    on whether the cookie is valid. Call Handler class
    read_cookie to access"""
    user_id = cookie.split('|')[0]
    return make_secure_cookie(user_id) == cookie



# Page specific common functions
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

	def check_admin(self):
		"""Checks to see if an admin user exists
		renders gen_admin if not"""
		c = users.all().filter("is_admin =", True).get()
		if c:
			return True
		else:
			return False

	def return_id_by_cookie(self):
		"""gets the users datastore id number from
		their cookie"""
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
		"""pass in text you want to preserve whitespace
		in while still keeping safe"""
		content = body.replace('\n', '<br>')
		return content

	def is_logged_in(self):
		"""checks if user is logged in so
		Log Out button appears appropriately"""
		if self.read_cookie:
			user_id = self.return_id_by_cookie()
			if user_id:
				logged_in = True
			else:
				logged_in = False
		else:
			logged_in = False
		return logged_in

class HomePage(Handler):
	def get(self):
		logged_in = self.is_logged_in()
		self.render('homepage.html', logged_in=logged_in)


class users(db.Model):
	"""DB stores site user data"""
	username = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	is_admin = db.BooleanProperty(default=False)
	join_date = db.DateTimeProperty(auto_now_add=True)
	liked_posts = db.StringListProperty()

	@classmethod
	def signup(cls, username, password, email=None, is_admin=None):
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
	"""DB that stores post data"""
	title = db.StringProperty(required=True)
	body = db.TextProperty(required=True)
	create_date = db.DateTimeProperty(auto_now_add=True)
	likes = db.IntegerProperty()
	dislikes = db.IntegerProperty()
	create_user = db.StringProperty(required=True)
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
	"""DB for comment data"""
	create_user = db.StringProperty(required=True)
	title = db.StringProperty(required=True)
	body = db.TextProperty(required=True)
	create_date = db.DateTimeProperty(auto_now_add=True)
	post = db.StringProperty(required=True)

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
	"""Class for registering a new user, if admin
	exists """
	def get(self):
		logged_in = self.is_logged_in()
		admin_made = self.check_admin()
		self.render("signup.html", logged_in=logged_in, admin_made=admin_made)

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
	"""class for logging in"""
	def get(self):
		logged_in = self.is_logged_in()
		self.render("login.html", logged_in=logged_in)

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
	"""Class to handle a successful login"""
	def get(self):
		user_id = self.return_id_by_cookie()
		if user_id:
			key = db.Key.from_path('users', user_id)
			user_entity = db.get(key)
			name = user_entity.username
			logged_in = True
			self.render("welcomepage.html", name=name, logged_in=logged_in)
		else:
			self.redirect("/blog/login")

class AdminPage(Handler):
	"""Admin only controls, allows admins to delete
	users, posts, and designate other users as admins"""
	def get(self):
		if self.read_cookie():
			user = users.find_by_id(self.return_id_by_cookie())
			logged_in = True
			c = db.GqlQuery("SELECT * from users")
			self.render("adminpage.html", users=c, user=user, logged_in=logged_in)
		else:
			error = "You must logged in to view this page!"
			self.render("adminpage.html", error=error, user=None)

class DeleteUser(Handler):
	"""Class that is called when delete user button is used"""
	def get(self, user_id):
		key = db.Key.from_path('users', int(user_id))
		c = db.get(key)
		c.delete()

		self.redirect("/blog/adminpage")

class DeleteAllPosts(Handler):
	"""Class to empty all posts on admin page"""
	def get(self):
		if self.read_cookie():
			user = users.find_by_id(self.return_id_by_cookie())
			if user.is_admin == True:

				for i in blogposts.all():
					db.delete(i)

				self.redirect('/blog')
			else:
				self.write("You do not have access to this function!")
		else:
			self.write("You do not have access to this function!")



class LogOut(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog/login')

class NewPost(Handler):
	"""checks user form input for validation and
	completeness, makes a new post."""
	def get(self):
		logged_in = self.is_logged_in()
		if logged_in:
			self.render("newpost.html", logged_in=logged_in)
		else:
			self.redirect('/blog/login')

	def post(self):
		if self.is_logged_in():

			params = dict()

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
	"""Class for viewing any single post."""
	def get(self, post_id):
		post = blogposts.post_by_id(post_id)
		if post:
			self.user = ""
			post_comments = comments.comments_by_post_id(str(post_id))
			logged_in = False
			if self.is_logged_in():
				self.user = users.find_by_id(self.return_id_by_cookie())
				logged_in = self.is_logged_in()
			self.render("postpage.html", post=post, user=self.user,
						 comments=post_comments, logged_in=logged_in)
		else:
			self.error(404)

class MainPage(Handler):
	"""Main page for viewing 10 most recent blog entries."""
	def get(self):
		logged_in = self.is_logged_in()
		posts = db.GqlQuery("SELECT * FROM blogposts order by create_date desc limit 10")
		current_user = ""
		if self.return_id_by_cookie():
			current_user = users.find_by_id(self.return_id_by_cookie())

		self.render("mainpage.html", posts=posts, 
			         current_user=current_user, logged_in=logged_in)

class LikePost(Handler):
	"""Caled when a post is liked."""
	def get(self, post_id):
		post = blogposts.post_by_id(post_id)
		if post:
			if self.is_logged_in():
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
		else:
			self.error(404)

class MyPosts(Handler):
	"""Class to view all of a users own posts."""
	def get(self):
		if self.is_logged_in():
			self.user = users.find_by_id(self.return_id_by_cookie())
			c = blogposts.all().filter('create_user =', self.user.username)
			logged_in = self.is_logged_in()
			d = c.get()
			if d:
				self.render("myposts.html", posts=c, logged_in=logged_in)
			else:
				message = "You have no posts! You need to gets to writing!"
				self.render("myposts.html", message=message, logged_in=logged_in)
		else:
			self.redirect('/blog/login')

class EditPost(Handler):
	"""class for editing a post."""
	def get(self, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		post = db.get(key)
		if post:
			if self.is_logged_in():
				logged_in = self.is_logged_in()
				user = users.find_by_id(self.return_id_by_cookie())
				if user.username == post.create_user or user.is_admin == True:
					self.render('editpost.html', post=post, logged_in=logged_in)
			else:
				self.write("You do not have access to this function!")
		else:
			self.error(404)

	def post(self, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		post = db.get(key)
		if post:
			self.title = self.request.get("title")
			self.body = self.request.get("body")

			if self.read_cookie():
				user = users.find_by_id(self.return_id_by_cookie())
				if user.username == post.create_user or user.is_admin == True:
					if self.title and self.body:
						post.title = self.title
						post.body = self.body
						post.put()
						self.redirect('/blog/postpage/%s' % str(post.key().id()))
					else:
						error = "Please enter a title and body"
						self.render("editpost.html", error=error)
				else:
					self.write("You do not have access to this function!")
			else:
				self.write("You do not have access to this function!")
		else:
			self.error(404)

class DeletePost(Handler):
	"""Delete a post."""
	def get(self, post_id):
		key = db.Key.from_path('blogposts', int(post_id))
		post = db.get(key)
		if post:
			if self.read_cookie():
				user = users.find_by_id(self.return_id_by_cookie())
				if user.username == post.create_user or user.is_admin == True:
					post.delete()
					self.redirect('/blog/myposts')
				else:
					self.write("You do not have access to this function!")
			else:
				self.write("You do not have access to this function!")
		else:
			self.error(404)

class Comment(Handler):
	"""Validate a comment form then post one."""
	def get(self, post_id):
		post = blogposts.post_by_id(post_id)
		if post:
			logged_in = self.is_logged_in()
			if self.is_logged_in():
				self.render('comment.html', post=post, logged_in=logged_in)
			else:
				self.redirect('/blog/login')
		else:
			self.error(404)

	def post(self, post_id):
		post = blogposts.post_by_id(post_id)
		if post:
			if self.is_logged_in():
				self.comment_user = users.find_by_id(self.return_id_by_cookie())
				self.title = self.request.get("title")
				self.body = self.request.get("body")
				self.post = post_id
				post = blogposts.post_by_id(post_id)
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
					self.render('comment.html', post=post, error_title=error_title,
												error_body=error_body, title=self.title,
												body=self.body)
			else:
				self.redirect('/blog/login')
		else:
			self.error(404)

class ViewComment(Handler):
	"""View an individual comment"""
	def get(self, comment_id):
		key = db.Key.from_path('comments', int(comment_id))
		comment = db.get(key)
		if comment:
			if self.is_logged_in():
				logged_in = self.is_logged_in()
				user = None
				if self.read_cookie():
					user = users.find_by_id(self.return_id_by_cookie())
				self.render("viewcomment.html", comment=comment, logged_in=logged_in, user=user)
			else:
				self.redirect('/blog/login')
		else:
			self.error(404)

class ChangePassword(Handler):
	"""Class for users to change their own password"""
	def get(self, user_id):
		logged_in = self.is_logged_in()
		self.render("changepassword.html", logged_in=logged_in)

	def post(self, user_id):
		key = db.Key.from_path('users', int(user_id))
		user = db.get(key)
		self.current_password = self.request.get("current_password")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		params = dict()
		error = False

		if not valid_password(self.password):
			error = True
			params['error_valid'] = "New password is not valid"

		if not self.password == self.verify:
			error = True
			params['error_verify'] = "Passwords do not match"

		if not check_pw(user.username, self.current_password, user.password):
			error = True
			params['error_current'] = "That is not the correct password"

		if error:
			self.render("changepassword.html", **params)
		else:
			user.password = make_pw(user.username, self.password)
			user.put()
			self.redirect('/blog')

class MakeAdmin(Handler):
	"""Class for admins to make other users admins"""
	def get(self, user_id):
		key = db.Key.from_path('users', int(user_id))
		user = db.get(key)

		if user.is_admin:
			user.is_admin = False
		else:
			user.is_admin = True

		user.put()
		
		self.redirect('/blog/adminpage')

class GenAdmin(Handler):
	"""Will generate a generic admin for first-time users,
	called on signup.html if check_admin returns no users with
	admin priveledges"""
	def get(self):
		password = make_pw("admin", "password")
		c = users(username="admin", password=password, is_admin=True)
		c.put()
		self.redirect('/blog/login')

class EditComment(Handler):
	"""Class used to edit comments"""
	def get(self, comment_id):
		key = db.Key.from_path('comments', int(comment_id))
		comment = db.get(key)
		if self.is_logged_in():
			if comment:
				self.render("editcomment.html", comment=comment)
			else:
				self.error(404)
		else:
			self.redirect('/blog/login')

	def post(self, comment_id):
		key = db.Key.from_path('comments', int(comment_id))
		comment = db.get(key)
		if comment:
			params = dict()
			error = False
			if self.is_logged_in():
				user = users.find_by_id(self.return_id_by_cookie())

				self.title = self.request.get("title")
				self.body = self.request.get("body")

				if not self.title:
					error = True
					params['title_error'] = "Please make sure there is a title"

				if not self.body:
					error = True
					params['body_error'] = "Please make sure there is a body"

				if not user.username == comment.create_user or user.is_admin == True:
					error = True
					params['access_error'] = "You do not have the proper credentials to edit this post!"

				if not error:
					comment.title = self.title
					comment.body = self.body
					comment.put()
					self.redirect('/blog/viewcomment/%s' % str(comment.key().id()))
				else:
					self.render("editcomment.html", comment=comment, **params)
			else:
				self.redirect('/blog/login')
		else:
			self.error(404)

class DeleteComment(Handler):
	def get(self, comment_id):
		key = db.Key.from_path('comments', int(comment_id))
		comment = db.get(key)
		if comment:
			post_key = db.Key.from_path('blogposts', int(comment.post))
			post = db.get(post_key)
			if self.is_logged_in():
				user = users.find_by_id(self.return_id_by_cookie())
				if user.username == comment.create_user or user.is_admin == True:
					comment.delete()
					self.redirect('/blog/postpage/%s' % str(post.key().id()))
				else:
					self.write("You don't have access to this function!")
			else:
				self.write("You don't have access to this function!")
		else:
			self.error(404)

		

app = webapp2.WSGIApplication([('/', HomePage),
							   ('/blog', MainPage),
							   ('/blog/signup', SignUp),
							   ('/blog/login', LogIn),
							   ('/blog/welcomepage', WelcomePage),
							   ('/blog/adminpage', AdminPage),
							   ('/blog/changepassword/(\d+)', ChangePassword),
							   ('/blog/deleteuser/(\d+)', DeleteUser),
							   ('/blog/makeadmin/(\d+)', MakeAdmin),
							   ('/blog/deleteallposts', DeleteAllPosts),
							   ('/blog/postpage/(\d+)', PostPage),
							   ('/blog/newpost', NewPost),
							   ('/blog/likepost/(\d+)', LikePost),
							   ('/blog/editpost/(\d+)', EditPost),
							   ('/blog/deletepost/(\d+)', DeletePost),
							   ('/blog/comment/(\d+)', Comment),
							   ('/blog/viewcomment/(\d+)', ViewComment),
							   ('/blog/myposts', MyPosts),
							   ('/blog/genadmin', GenAdmin),
							   ('/blog/editcomment/(\d+)', EditComment),
							   ('/blog/deletecomment/(\d+)', DeleteComment),
							   ('/blog/logout', LogOut)],
								debug=True)