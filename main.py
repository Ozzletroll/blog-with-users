import flask
import werkzeug
from flask import Flask, render_template, redirect, request, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps

import forms
from forms import CreatePostForm
from flask_gravatar import Gravatar


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)


# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250))
    email = db.Column(db.String(250))
    password = db.Column(db.String(250))

    # Define relationship to user's posts
    posts = relationship("BlogPost", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Define relationship to post's author
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")


# Create database
# with app.app_context():
#     db.create_all()


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.get_id() == "1":
            return function(*args, **kwargs)
        else:
            return abort(403)
    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    # Create register form
    form = forms.RegisterUserForm()

    if form.validate_on_submit():

        user = User()
        user.username = request.form["username"]
        user.email = request.form["email"]

        # Hash and salt password
        password = request.form["password"]
        hash_and_salted_password = werkzeug.security.generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=8
        )

        user.password = hash_and_salted_password

        # Check if username and email are already in database
        email_lookup = db.session.query(User).filter_by(email=user.email).first()
        username_lookup = db.session.query(User).filter_by(username=user.username).first()

        if email_lookup:
            flash("Email already registered, please login instead.")
            return redirect(url_for("register"))
        elif username_lookup:
            flash("Username already taken, please choose another.")
            return redirect(url_for("register"))
        else:
            # Commit user to db
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():

    form = forms.LoginForm()

    if form.validate_on_submit():
        email = request.form["email"]
        password = request.form["password"]

        # Find user and check password
        user = db.session.query(User).filter_by(email=email).first()

        if user and werkzeug.security.check_password_hash(pwhash=user.password, password=password):
            # Login
            login_user(user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Incorrect password or username.")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = forms.CommentForm()

    if form.validate_on_submit():
        pass

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
