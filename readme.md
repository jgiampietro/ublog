# Udacity Multi-User Blog

## Purpose

This is a project for Udacity's full-stack nano-degree course. 

## Installation

To run the app locally on your hardware, complete the following:

1. Install Python 2.7.13 found [here](https://www.python.org/downloads)
2. Install the Google App Engine SDK found [here](https://cloud.google.com/appengine/docs/python/download)
3. Clone the repository using the following URL `https://github.com/jgiampietro/ublog.git`
4. Open your command line or similar and navigate to the cloned directory
5. Type ```dev_appserver.py .``` and be sure not to forget the trailing ```.```
6. Open your browser to localhost:8080

Note that you can view the actual database for this project by navigating to localhost:8000/datastore once the VM is running.

## Working Demo
A demo of this project can be found [here](https://forms-projects.appspot.com)

## Features
#### Features called for in rubric
The rubric calls for the blog to be able to do the following:
* Users can securely log in. Passwords stored are hashed.
* Users can log out. The log out option is only displayed to users who are logged in.
* Users can register, with basic validation being carried out on their input
* Users can like all posts but their own, and only when logged in
* Users can comment on posts when logged in
* Users can edit and delete only their own post
* Users can view any single post on its own "Permalinked" page.

#### Additional features
An admin function has been added. There is a default administrator, but that admin can make any user an admin, as well.
Admins can delete all posts, edit or delete any particular post, delete users and toggle whether a user is an admin or not.

## First Use Considerations
Upon launching the app locally for the first time, you will want to have an admin user to make administration easier. Go to the Signup page to set up your first admin user.
Note that the user will be created as username "admin" and password of "password". You can change the password from the admin page if you like. Be advised this will cause data inconsistency issues if you have already registered a user named "admin" so be sure to do this first. If you do not wish to have your admin username be "admin", simply follow the steps below:

1. Generate the admin user as above
2. You will be redirected to the login page. Click Logout in the nav bar.
3. You are redirected to signup. Register your preferred admin username and password
4. Click logout as step 2.
5. Click login in the navbar
6. Log in as the admin user created in step 1 using username "admin" and password "password"
7. Navigate to the admin page
8. Find the user you added in step 3, click the button to toggle admin priveledges.
9. Logout, then login is as user from step 3.
10. Navigate to the admin page and delete the admin user.