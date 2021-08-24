from flask.wrappers import Request
from flask_app import app
from flask import render_template, redirect, request, session, flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
import re


@app.route("/")
def login():
    return render_template("login.html")


@app.route("/login_user", methods=["POST"])
def login_user():
    data = {"username": request.form["username"]}
    user_in_db = User.get_by_username(data)
    if not user_in_db:
        flash("Account doesn't exist")
        return redirect("/")
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        flash("Account doesn't exist")
        return redirect("/")
    session['user_id'] = user_in_db.id
    return redirect("/dashboard")


@app.route("/register_user", methods=["POST"])
def register_user():
    # if User.register_validate(request.form) == False:
    #     return redirect("/")
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        "username": request.form["username"],
        "password": pw_hash,
    }
    user_id = User.save(data)
    session['user_id'] = user_id
    return redirect("/dashboard")


@app.route("/delete_session")
def delete_session():
    session.clear()
    return redirect("/")

@app.route("/dashboard")
def dashboard():    
    context = {
        "user" : User.get_one(session["user_id"]),  
        }
    
    
    return render_template("dashboard.html", **context )

@app.route("/match", methods=["POST"])
def match():
    regular_expression = request.form["regular_expression"]
    # print("*"*80)
    # regular_expression= r"'^c./t+$"
    regular_expression = re.compile('.*({}).*'.format(regular_expression))
    print("*"*80)
    print(regular_expression)
    print("*"*80)
    test_string = request.form["test_string"]
    is_valid = regular_expression.match(test_string)
    print(is_valid)
    print("*"*80)
    if is_valid == None:
        session["valid"] = False
    else:
        session["valid"] = True   
    return redirect ("/dashboard")