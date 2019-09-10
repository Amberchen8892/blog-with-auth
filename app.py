from flask import Flask, render_template, url_for, redirect, flash, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from datetime import datetime
from sqlalchemy import desc


# setting app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
login = LoginManager(app)
# login.init_app(app)
db = SQLAlchemy(app)
migrate = Migrate(app,db)


# must have for login
@login.user_loader
def load_user(id):
  return Users.query.get(int(id))

# difine connection to DB
POSTGRES = {
    'user': 'phuong',
    'pw': '123',
    'db': 'real_blog',
    'host': 'localhost',
    'port': 5432,
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES

# setting class
class Follows (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer,db.ForeignKey('users.id'), unique=True)
    followed_id =db.Column(db.Integer,db.ForeignKey('users.id'), unique=True)


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False) 
    posts = db.relationship('Posts', backref='users', lazy='dynamic')
    comments = db.relationship('Comments',cascade="all, delete-orphan", backref='users', lazy='dynamic')
    likes = db.relationship('PostLikes',  backref='users', lazy='dynamic')
    flags = db.relationship('Flags', backref='users', lazy='dynamic')
    follower = db.relationship('Follows', foreign_keys=[Follows.follower_id], backref=db.backref('follower', lazy='joined'),lazy='dynamic',cascade="all, delete-orphan")
    followed = db.relationship('Follows', foreign_keys=[Follows.followed_id], backref=db.backref('followed', lazy='joined'),lazy='dynamic',cascade="all, delete-orphan")

    
    
    def set_password(self,password):
        self.password = generate_password_hash(password)
    def check_password_hash(self, password):
        return check_password_hash(self.password, password)

    def like(self,post):
        if not self.has_liked_post(post):
            like=PostLikes(user_id=self.id, post_id=post.id)
            db.session.add(like)
    def unlike(self,post):
        if self.has_liked_post(post):
            PostLikes.query.filter_by(user_id=self.id,post_id=post.id).delete()
    def has_liked_post(self,post):
        return PostLikes.query.filter_by(user_id=self.id,post_id=post.id ).count()

    def flag(self,post):
        if not self.has_flagged_post(post):
            flag=Flags(user_id=self.id, post_id=post.id)
            db.session.add(flag)
    def unflag(self,post):
        if self.has_flagged_post(post):
            Flags.query.filter_by(user_id=self.id,post_id=post.id).delete()
    def has_flagged_post(self,post):
        return Flags.query.filter_by(user_id=self.id,post_id=post.id ).count()

    
class Posts (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime)
    updated = db.Column(db.DateTime)
    view_count= db.Column(db.Integer, default=0)
    author = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = db.relationship('Comments',cascade="all, delete-orphan", backref="posts", lazy="dynamic")
    likes= db.relationship('PostLikes', backref="posts", lazy="dynamic")
    flags = db.relationship('Flags', backref="posts", lazy="dynamic")
# backref =  name of class , foreignkey ('user.id) read more about lazy, secondary????

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    updated = db.Column(db.DateTime)
    author = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    
class PostLikes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id= db.Column(db.Integer, db.ForeignKey('posts.id'))

class Flags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id= db.Column(db.Integer, db.ForeignKey('posts.id'))


db.create_all()



# setting form 
class Signup(FlaskForm):
    username = StringField('Username', validators=[DataRequired('Please enter your username'), Length(min =3, max= 100, message="at least 3 chars and at most 100 chars") ])
    email = StringField('Email', validators=[DataRequired('Please enter your email address'), Email('Please input the valid email')])
    password = PasswordField('Password', validators=[DataRequired('Please enter your password'), EqualTo('confirm', message = 'Password must match')])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Sign Up')
    def validate_username(self, field):
        if Users.query.filter_by(username=field.data).first():
            raise ValidationError('Your username has been registered')
    def validate_email(self, field):
        if Users.query.filter_by(email=field.data).first():
            raise ValidationError('Your email has been registered')

class Login(FlaskForm):
    email = StringField('Email', validators=[DataRequired('Please enter your email address'),])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class Create_post(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min =3, max=150, message="at least 3 chars and at most 150 chars")])
    body = StringField('Description', validators=[DataRequired(), Length(min =3, max=500, message="at least 3 chars and at most 500 chars")])
    submit = SubmitField('Create')

class New_comment(FlaskForm):
    body = StringField('Comment Content', validators=[DataRequired(), Length(min =3, max=500, message="at least 3 chars and at most 500 chars")])
    submit = SubmitField('Comment')


# setting route
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods = ['POST', 'GET'])
def signup():
    form = Signup()
    if request.method == 'POST':
        if form.validate_on_submit():
            u = Users(username=form.username.data,
                       email = form.email.data )
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            login_user(u)
            return redirect(url_for('profile'))
        else:
            print(form.errors)
            for field_name, errors in form.errors.items():
                flash(errors)
    return render_template('signup.html', form = form)


    

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = Login()
    if request.method == 'POST':
        check = Users.query.filter_by(email = form.email.data).first()
        if check:
            if check.check_password_hash(form.password.data):
                login_user(check)
                return redirect(url_for('profile'))
            else:
                flash(['your password is incorrect'])
                return redirect(url_for('login'))

        else:
            flash(["email address not exist"])
            return redirect(url_for('signup'))
    return render_template('signin.html', form = form)

    
    
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


    

@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    posts = Posts.query.filter_by(author= current_user.id).all()
    form = Create_post()
    if request.method == 'POST':
        p = Posts(title=form.title.data, 
                  body = form.body.data,
                  created = datetime.now())
        current_user.posts.append(p)
        db.session.add(p)
        db.session.commit()
        return redirect(url_for('profile'))
    friends= Follows.query.filter_by(follower_id=current_user.id).all()
    # print("==========", friends)
    # for i in friends:
    #     print("======", i.followed.username)
    return render_template('profile.html', form = form, posts=posts, friends=friends)

@app.route('/posts')
@login_required
def posts():
    posts = Posts.query.all()
    return render_template('posts.html', posts=posts)

@app.route('/editpost/<id>', methods = ['POST', 'GET'])
@login_required
def edit_post(id):
    ref = request.args.get('ref')
    form = Create_post()
    post = Posts.query.filter_by(id=id, author= current_user.id).first()
    if not post:
        flash(["you are not allowed to edit this post"])
        return redirect(url_for("posts"))
    else:
        if request.method == 'POST':
            post.title = form.title.data
            post.body = form.body.data
            post.updated = datetime.now()
            db.session.commit()
            if ref == "profile":
                return redirect(url_for("profile"))
            elif ref == 'posts':
                return redirect(url_for("posts"))
        # return redirect(url_for('posts'))
    return render_template('editpost.html', form = form, post=post )

@app.route('/deletepost/<id>', methods=['GET'])
@login_required
def delete_post(id):
    ref = request.args.get('ref')
    post = Posts.query.filter_by(id=id, author= current_user.id).first()
    if post:
        db.session.delete(post)
        db.session.commit()
        if ref == "profile":
                return redirect(url_for("profile"))
        elif ref == 'posts':
                return redirect(url_for("posts"))
        else:
            redirect(url_for('profile'))
    else: 
        flash(['You are not allowed to delete this post'])
    return redirect(url_for('profile'))

@app.route('/single_post/<id>/comments', methods = [ 'POST'])
def create_comment(id):
   
    if request.method == 'POST':
        post = Posts.query.filter_by(id=id)
        c = Comments(body = request.form['body'], created = datetime.now(), author = current_user.id, post = id)
        db.session.add(c)
       
        db.session.commit()
        return redirect(url_for('single_post', id=id))

@app.route('/single_post/<id>', methods = [ 'POST', 'GET'])
def  single_post(id):
    form = New_comment()
    post = Posts.query.filter_by(id =id).first()
    post.view_count += 1 
    db.session.commit()
    
    if not post:
        flash(["post is not found"])
        return redirect(url_for('posts'))
    else:
        comments = Comments.query.filter_by(post=id).all()
        return render_template('single_post.html', form = form, post = post, comments = comments)


@app.route('/single_post/<id>/<action>')
@login_required
def like_action(id, action):
    ref = request.args.get('ref')
    form = New_comment()
    post=Posts.query.filter_by(id=id).first()
    for i in post.likes: 
        # print('==============',i.user_id)
        user_likes = Users.query.filter_by(id=i.user_id).all()
        for i in user_likes: 
            print('=======', i.username)    
    # p.likes.count()
    if action == 'like':
        current_user.like(post)
        db.session.commit()
        if ref == "profile":
                return redirect(url_for("profile"))
        elif ref == 'posts':
                return redirect(url_for("posts"))
        else:
            redirect(url_for('profile'))
    if action == 'flag':
        current_user.flag(post)
        db.session.commit()
        if ref == "profile":
                return redirect(url_for("profile"))
        elif ref == 'posts':
                return redirect(url_for("posts"))
        else:
            redirect(url_for('profile'))
    if action == 'unlike':
        current_user.unlike(post)
        db.session.commit()
        if ref == "profile":
                return redirect(url_for("profile"))
        elif ref == 'posts':
                return redirect(url_for("posts"))
        else:
            redirect(url_for('profile'))
    if action == 'unflag':
        current_user.unflag(post)
        db.session.commit()
        if ref == "profile":
                return redirect(url_for("profile"))
        elif ref == 'posts':
                return redirect(url_for("posts"))
        else:
            redirect(url_for('profile'))
    return render_template('single_post.html', post=post, form=form)



@app.route('/editcomment/<id>', methods=['POST', 'GET'])
@login_required
def edit_comment(id):
    form = New_comment()
    comment= Comments.query.filter_by(id=id, author= current_user.id).first()
    post_id = comment.post
    if not comment:
        flash(["you are not allowed to edit this comment"])
        return redirect(url_for("posts"))
    else:
        if request.method == 'POST':
            comment.body = form.body.data
            comment.updated= datetime.now()
            db.session.commit()
            return redirect(url_for('edit_comment', id=id))
    post = Posts.query.filter_by(id=post_id)
    return render_template('editcomment.html', comment=comment, post=post, form=form)
    
@app.route('/test')
def test():
    return render_template('test.html')


@app.route('/comments/<id>/delete', methods=['GET'])
@login_required
def delete_comment(id):
    comment= Comments.query.filter_by(id=id, author= current_user.id).first()
    post_id = comment.post
    if comment:
        db.session.delete(comment)
        db.session.commit()
    else: 
        flash(['You are not allowed to delete this comment'])
    return redirect(url_for('single_post', id = post_id))


@app.route('/popular')
@login_required
def most_popular():
    posts=Posts.query.order_by(Posts.view_count.desc()).all()
    return render_template("most_popular.html", posts=posts)

@app.route('/people')
def find_friends():
    users= Users.query.all()
    return render_template('find_friends.html', users=users)


@app.route('/friends')
@login_required
def friends():
    friends= Users.followed.all()
    print("Phuongggg", friends)
    return render_template('profile.html', friends=friends)

@app.route('/user/<id>/follow', methods=['POST', 'GET'])
@login_required
def follow(id):
    if current_user.id == int(id):
        flash("You can't follow yourself")
    else:
        has_follow = Follows.query.filter_by(
            followed_id=id, follower_id=current_user.id).first()
        if has_follow:
            db.session.delete(has_follow)
        else:
            new_follow = Follows(followed_id=id, follower_id=current_user.id)
            db.session.add(new_follow)
        db.session.commit()
   
    return redirect(url_for("profile", id=id))


if __name__ == '__main__':
  app.run(debug=True)