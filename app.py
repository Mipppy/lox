from flask import Flask, flash, redirect, render_template, request, session, g
from cs50 import SQL
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import HTTPException
from flask_mail import Mail, Message
from helpers import *
import os, stripe, random, string, sys, io
from datetime import datetime
stripe.api_key = os.environ['STRIPE_SECRET_KEY']
DATABASE = 'sql.db'
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'loxofbagelsandmoor@gmail.com'
app.config['MAIL_PASSWORD'] = 'glfp hkkk hbqw fkbe'
app.config['MAIL_DEFAULT_SENDER'] = 'confirmation@loxofbagelsandmoor.com'
Session(app)
mail = Mail(app)
db = SQL("sqlite:///sql.db")
endpoint_secret = 'whsec_fd1c125e6aa814b582e69f0295f7b5d74887e719567af9aab4e77d825493b1e3'
app.jinja_env.filters["usd"] = usd


# get console for admin page


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route('/')
def index():
    try:
        username = db.execute("SELECT name FROM users WHERE id = ?", session["user_id"])
        username = username[0]['name']
    except:
        # not logged in
        username = ""

    return render_template("index.html", username=username)
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("name"):
            flash("You must provide a name!")
            return render_template("register.html")
        elif not request.form.get("password"):
            flash("You must provide a password!")
            return render_template("register.html")
        elif not request.form.get("confirmation"):
            flash("You must confirm your password!")
            return render_template("register.html")
        elif not request.form.get("email"):
            flash("Enter an email address!")
            return render_template("register.html")    
        if request.form.get("password") != request.form.get("confirmation"):
            flash("Passwords don't match!")
            return render_template("register.html")
        if request.form.get("email") != request.form.get("confirmemail"):
            flash("Emails don't match!")
            return render_template("register.html")
        
        emailBool = db.execute("SELECT email FROM users WHERE email = ?", request.form.get("email"))
        if len(emailBool) == 1:
            flash("An account with this email already exists!")
            return render_template("register.html")
        registersBool = db.execute("SELECT email FROM registers WHERE email = ?", request.form.get("email"))
        if len(registersBool) == 1:
            flash("An account with this email already exists!")
            return render_template("register.html")
        verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        db.execute("INSERT INTO registers (email, password, code, timestamp,name) VALUES (?, ?, ?, ?,?)", request.form.get("email"), request.form.get("password"), verification_code, datetime.now(), request.form.get("name"))
        session["neededForASecond"] = request.form.get("email")
        send_email(request.form.get("email"), "Verification Code", verification_code, "nothing :D")
        return redirect("/verify")
    else:
        return render_template("register.html")
    
@app.route('/verify', methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        if not request.form.get("code"):
            flash("Enter a code!")
            return render_template("verify.html")
        neededData = db.execute("SELECT email, password, name,code FROM registers WHERE email = ?", session["neededForASecond"])
        session.pop("neededForASecond")
        if request.form.get("code") == neededData[0]['code']:
            db.execute("INSERT INTO users (name, hash, email) VALUES (?, ?, ?)",neededData[0]["name"], generate_password_hash(neededData[0]["password"]), neededData[0]["email"]) 
            return redirect("/login")
        else:
            flash("Code does not match")
            return render_template('verify.html')
    else:
        return render_template("verify.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("email"):
            flash("Enter a username!")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Enter a password!")
            return render_template("login.html")
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username/password!")
            return render_template("login.html")
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/menu", methods=["GET", "POST"])
def menu():
    if request.method == "POST":
        if not session["user_Id"]:
            return redirect("/login")
        
    else:
        products = get_products()
        return render_template("menu.html", products=products)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("Successfully logged out!")
    return redirect("/")

def get_products():
    products = db.execute("SELECT * FROM products")
    return products

@app.route('/products/<string:product>', methods=['GET', 'POST'])
def product(product):
  if request.method == "POST":
        redirect("/cart")
        product = request.form.get("product")
        quanity = request.form.get("quanity")
        modifiers = request.form.get("modifiers")
        price = request.form.get("price")
        db.execute("INSERT INTO cart (user, product, quanity, modifiers,price) VALUES (?,?,?,?,?)", session["user_id"], product, quanity, modifiers, price)
        return redirect("/cart")
  else:
        product_info = db.execute("SELECT * FROM products WHERE shortname = ?", product)
        return render_template("product.html", product=product_info[0])

@app.route('/cart', methods=["GET", "POST"])
@login_required
def cart():
    cart = db.execute("SELECT * FROM CART WHERE user = ?", session["user_id"])
    if request.method == "POST":
        encoder = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        price_total = 0
        for index in cart:
            price_total += (index['price'] * index['quanity'])
        stripe_payment_processing = stripe.checkout.Session.create(
            line_items = [
                {
                    'price_data': {
                        'product_data': {
                            'name': 'Lox of Bagels Order'
                        },
                        'unit_amount': int(price_total * 1.07),
                        'currency': 'usd',
                    },
                    'quantity' : 1,
                }
            ],
            payment_method_types=['card'],
            mode='payment',
            success_url=request.host_url + f'order?key={generate_password_hash(encoder)}&success=true',
            cancel_url=request.host_url + f'order?key=&success=',
        )
        session["stripeURL"] = encoder
        return redirect(stripe_payment_processing.url)
    else:
        total_price = 0
        for product in cart:
            total_price += product["price"] * product["quanity"]
        fees_total_price = total_price * 1.07
        return render_template("cart.html", cart=cart, total_price=total_price, fees_total_price=fees_total_price)

@app.route('/order', methods=["GET"])
@login_required
def order():
    success = request.args.get('success', default=False)
    cart = db.execute("SELECT * FROM CART WHERE user = ?", session["user_id"])

    if check_password_hash(request.args.get('key', default=""),session['stripeURL']):
        id = generate_unique_id()
        for product in cart:
            db.execute("INSERT INTO orders (orderid, user, product,quantity,modifiers,completed,total,date) VALUES (?,?,?,?,?,?,?,?)", id,session["user_id"], product['product'], product['quanity'],product['modifiers'],0,product['price'], datetime.now())
    else:
        success = False
    if success:
        db.execute("DELETE FROM cart WHERE user = ?", session["user_id"])        

    active_orders = db.execute("SELECT * FROM orders WHERE completed = ?", 0)
    range1_minutes = len(active_orders) * 5
    range2_minutes = len(active_orders) * 8
    range2_hours = range2_minutes // 60
    range2_minutes %= 60
    range1_hours = range1_minutes // 60
    range1_minutes %= 60

    range1 = f"{range1_hours} hours {range1_minutes} minutes"
    range2 = f"{range2_hours} hours {range2_minutes} minutes"
    range = f"{range1} - {range2}"
    return render_template("order.html", success=success, range=range)
@app.route('/orders', methods=["GET", "POST"])
@login_required
def orders():
    if request.method == "POST":
        order_id = request.form.get("product")
        order_data = db.execute("SELECT * FROM orders WHERE orderid = ? AND user = ?", order_id, session["user_id"])
        for product in order_data:
            db.execute("INSERT INTO cart (user, product, quanity, modifiers, price) VALUES (?, ?, ?, ?, ?)",session["user_id"], product["product"], product["quantity"], product["modifiers"], product["total"])
        flash(f'Successfully added order: {order_id} to your cart!')
        return redirect("/orders")
    else:
        orders = db.execute("SELECT DISTINCT orderid,date FROM orders WHERE user = ? ORDER BY date DESC", session["user_id"])
        completed = db.execute("SELECT completed FROM orders WHERE user = ?", session["user_id"])
        if completed == 1:
            completed = True
        else:
            completed = False
        return render_template("orders.html", orders=orders, completed=completed)

@app.route('/orders/<string:order_id>', methods=["GET", "POST"])
@login_required
def order_page(order_id):
    if request.method == "POST":
        order_info = request.form.get("order_info")
        list_of_products = list(eval(order_info))
        for product in list_of_products:
            db.execute("INSERT INTO cart (user, product, quanity, modifiers, price) VALUES (?, ?, ?, ?, ?)",session["user_id"], product["product"], product["quantity"], product["modifiers"], product["total"])
        flash(f'Successfully added order: {order_id} to your cart!')
        return redirect("/orders")
    else:
        try:
            order_info = db.execute("SELECT * FROM orders WHERE orderid = ? AND user = ?", order_id, session["user_id"])
            completed = db.execute("SELECT completed FROM orders WHERE user = ? AND orderid = ?", session["user_id"], order_id)
            if completed == 1:
                completed = True
            else:
                completed = False
            return render_template("order_page.html", order_info=order_info, order_id=order_id, completed=completed)
        except Exception as e:
            return redirect("/404")

@app.errorhandler(HTTPException)
def handle_exception(e):
    error_info = {
        "code": e.code,
        "name": e.name,
        "description": e.description,
    }
    return render_template("error.html", error_info=error_info), e.code

def send_email(to, subject,code,type_of):
    if type_of == "username":
        msg = Message(
        subject,
        recipients=[to],
        html=f'<p>Your username is: </p> <br> <h1>{code}</h1>',
        sender="confirmation@loxofbagelsandmoor.com",
        )      
    else:
        msg = Message(
        subject,
        recipients=[to],
        html=f'<p>Your code is: </p> <br> <h1>{code}</h1>',
        sender="confirmation@loxofbagelsandmoor.com",
        )
    mail.send(msg)

@app.route('/removefromcart', methods=["POST"])
def remove_from_cart():
    product = request.form.get("productid")
    db.execute("DELETE FROM cart WHERE user = ? AND id = ?", session["user_id"], product)
    flash("Successfully removed from cart")
    return redirect("/cart")

@app.route('/password_reset', methods=["GET", "POST"])
def pwd_reset():
    if request.method == "POST":
        if not request.form.get("username"):
            flash("You must provide a username!")
            return render_template("register.html")
        elif not request.form.get("password"):
            flash("You must provide a password!")
            return render_template("register.html")
        elif not request.form.get("confirmation"):
            flash("You must confirm your password!")
            return render_template("register.html")
        if request.form.get("password") != request.form.get("confirmation"):
            flash("Passwords don't match!")
            return render_template("register.html")

        email = db.execute("SELECT email FROM users WHERE username = ?", request.form.get("username"))
        if not email:
            flash("Invalid account details")
            return render_template("password_reset.html")
        verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        session['verification_data'] = {'email': email, 'code': verification_code, 'username': request.form.get("username"), 'password': request.form.get("password")}
        send_email(email[0]['email'], "Verify your new password", verification_code, "nothing again :D")
        return redirect("/verify_new")
    else:
        return render_template("password_reset.html")

@app.route("/verify_new", methods=["GET", "POST"])
def new_pas_verify():
    if request.method == "POST":
        if not request.form.get("code"):
            flash("Enter a code!")
            return render_template("verify.html")
        if request.form.get("code") == session['verification_data']['code']:
            db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(session['verification_data']['password']), session['verification_data']['username'])
            return redirect("/login")
        else:
            flash("Code does not match")
            return render_template('verify.html')
    else:
        email = session['verification_data']['email']
        return render_template("verify_new_pwd.html",email=email[0]['email'])
    
@app.route("/user_reset", methods=["GET", "POST"])
def user_reset():
    if request.method == "POST":
        if not request.form.get("email"):
            flash("You must provide a email!")
            return render_template("user_reset.html")
        elif not request.form.get("password"):
            flash("You must provide a password!")
            return render_template("user_reset.html")
        pwd = db.execute("SELECT hash FROM users WHERE email = ?", request.form.get("email"))
        userinput = str(request.form.get("password"))
        if not check_password_hash(pwd[0]['hash'],userinput):
            flash("Password is incorrect!")
            return render_template("user_reset.html")
        email = request.form.get("email")
        username = db.execute("SELECT username FROM users WHERE email = ?", email)
        username = username[0]['username']
        send_email(email, "Your username:", username, "username")
        return redirect("/login")
    else:
        return render_template("user_reset.html")

@app.route("/superuser/admin", methods=["GET", "POST"])
@login_required
def admin_login():
    if request.method == "POST":
        try:
            passkey = "1981"
            user_passkey = request.form.get("passkey")
            if passkey != user_passkey:
                flash("You aren't supposed to be here!")
                return redirect("/404")
            logged_in_user = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
            if not check_admin(session["user_id"]):
                return redirect("/404")
            
            active_orders = db.execute("SELECT * FROM orders WHERE completed = ? GROUP BY orderid", 0)
            for user in active_orders:
                user["user"] = db.execute("SELECT username FROM users WHERE id = ?", user["user"])
            return render_template("admin_home.html", active_orders=active_orders)
        except Exception as e:
            return redirect("/404")
    else:
        if not check_admin(session["user_id"]):
            return redirect("/404")
        return render_template("admin_login.html")
@app.route("/superuser/admin_site_data", methods=["POST"])
def adminsitedata():
    if not check_admin(session["user_id"]):
        return redirect("/404")
    site_data = db.execute("SELECT * FROM all_time_site_data")
    render_template("admin_site_data.html", site_data=site_data[0])
    return redirect("/superuser/admin")


if __name__ == '__main__':
  app.run()
