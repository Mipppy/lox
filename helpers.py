from flask import Flask, flash, redirect, render_template, request, session, g
from cs50 import SQL
from flask_session import Session
from functools import wraps
import random
db = SQL("sqlite:///sql.db")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def usd(value):
    value = value/100
    return f"${value:,.2f}"

def generate_unique_id():
		is_id_unique = False
		id= 0
		while is_id_unique == False:
				id = random.randint(-9999999999999,9999999999999)
				ids = db.execute("SELECT orderid FROM orders")
				for unqiue_id in ids:
						if unqiue_id["orderid"] == id:
								is_id_unique = False
						else:
								is_id_unique = True
		return id

def check_admin(user):
	logged_in_user = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
	if logged_in_user[0]['username'] != "lox admin":
		return None
	else:
		return True
