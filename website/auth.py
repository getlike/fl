from flask import Blueprint, render_template, request, flash, redirect, url_for

from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    data = request.form

    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Login удачно))', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Login не очень))', category='error')
        else:
            flash('А ты регался?))', category='error')

    # print(data['email'])#тут можно получить пост
    return render_template("login.html")


@auth.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        print(request.form['email'])
        email = request.form['email']
        first_name = request.form['firstName']
        password1 = request.form['password1']
        password2 = request.form['password2']
        post_req = request.form
        # for pos in post_req.values():
        #     print(pos)
        user = User.query.filter_by(email=email).first()

        if user:
            flash('Алреди с нами', category='error')
        elif len(post_req.get('email')) < 3:
            flash('Email to short', category='error')
        elif len(post_req.get('firstName')) < 2:
            flash('Name to short', category='error')
        elif post_req.get('password1') != post_req.get('password1'):
            flash('passwords not equals', category='error')
        elif len(post_req.get('password1')) < 7:
            flash('Password to short', category='error')
        else:
            new_user = User(email=email, first_name=first_name,
                            password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Acc created', category='success')
            return redirect(url_for('views.home'))
    return render_template("signup.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))