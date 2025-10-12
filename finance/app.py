import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM stock WHERE id = ?", session["user_id"])
    all_data = []
    sum_total = 0
    cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    for row in stocks:
        data = lookup(row["stock_name"])
        total = data["price"] * row["stock_number"]
        sum_total += total
        all_data.append((data["name"],row["stock_number"], data["price"], total, data["symbol"]))
    return render_template("index.html", data=all_data, shares_total=sum_total, cash=cash)


@app.route("/inter", methods=["POST"])
@login_required
def inter():
    num = int(request.form.get("shares"))
    if num > 0:
        data = lookup(request.form.get("symbol"))
        if not data:
            return apology("Stock does not exist", 400)
        else:
            if num <0:
                return apology("Stock number lower than zero", 400)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            if cash< data["price"]*num:
                return apology("insufficient cash", 400)
            else:
                ncash = cash - (data["price"]*num)
                stock = db.execute("SELECT stock_name FROM stock WHERE id = ?", session["user_id"])
                if any(sname["stock_name"] == data["symbol"] for sname in stock):
                    db.execute("UPDATE stock SET stock_number = stock_number + ? WHERE id = ? AND stock_name = ?",num, session["user_id"], data["symbol"])
                else:
                    db.execute("INSERT INTO stock (id, stock_name, stock_number) VALUES (?, ?, ?)", session["user_id"], data["symbol"], num)
                db.execute("UPDATE users SET cash = ? WHERE id =?", ncash, session["user_id"])
                db.execute("INSERT INTO transactions (id, stock_name, shares, stock_price, type) VALUES (?, ?, ?, ?, ?)", session["user_id"], data["symbol"], num, data["price"], 'buy')
                return redirect("/")
    elif num < 0:
        num = abs(num)
        data = lookup(request.form.get("symbol"))
        if not data:
            return apology("Stock does not exist", 400)
        else:
            if num <0:
                return apology("Stock number lower than zero", 400)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            stock = db.execute("SELECT * FROM stock WHERE id = ? AND stock_name = ?", session["user_id"], data["symbol"])
            if not stock:
                return apology("You don't own that stock", 400)
            stock_number = stock[0]["stock_number"]
            if stock_number < num:
                return apology("Sorry, insufficient shares number in your account", 400)
            else:
                ncash = cash + (data["price"]*num)
                if stock_number == num:
                    db.execute("DELETE FROM stock WHERE id = ? AND stock_name = ?", session["user_id"], data["symbol"])
                else:
                    db.execute("UPDATE stock SET stock_number = stock_number - ? WHERE id = ? AND stock_name = ?",num, session["user_id"], data["symbol"])
                db.execute("UPDATE users SET cash = ? WHERE id =?", ncash, session["user_id"])
                db.execute("INSERT INTO transactions (id, stock_name, shares, stock_price, type) VALUES (?, ?, ?, ?, ?)", session["user_id"], data["symbol"], num, data["price"], 'sell')
                return redirect("/")
    else:
        return redirect("/")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method=="POST":
        num = int(request.form.get("shares"))
        data = lookup(request.form.get("symbol"))
        if not data:
            return apology("Stock does not exist", 400)
        else:
            if num <0:
                return apology("Stock number lower than zero", 400)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            if cash< data["price"]*num:
                return apology("insufficient cash", 400)
            else:
                ncash = cash - (data["price"]*num)
                stock = db.execute("SELECT stock_name FROM stock WHERE id = ?", session["user_id"])
                if any(sname["stock_name"] == data["symbol"] for sname in stock):
                    db.execute("UPDATE stock SET stock_number = stock_number + ? WHERE id = ? AND stock_name = ?",num, session["user_id"], data["symbol"])
                else:
                    db.execute("INSERT INTO stock (id, stock_name, stock_number) VALUES (?, ?, ?)", session["user_id"], data["symbol"], num)
                db.execute("UPDATE users SET cash = ? WHERE id =?", ncash, session["user_id"])
                db.execute("INSERT INTO transactions (id, stock_name, shares, stock_price, type) VALUES (?, ?, ?, ?, ?)", session["user_id"], data["symbol"], num, data["price"], 'buy')
                return redirect("/")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute("SELECT * FROM transactions WHERE id = ?", session["user_id"])
    all_data = []
    for row in stocks:
        data = lookup(row["stock_name"])
        all_data.append((data["name"],row["shares"], row["stock_price"], row["type"], row["time"]))
    return render_template("history.html", data=all_data)
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    elif request.method == "POST":
        data = lookup(request.form.get("symbol"))
        if data:
            money = usd(data["price"])
            return render_template("quoted.html", data=data, money=money)
        return apology("That stock is not available", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    users = db.execute("SELECT username FROM users")
    name = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if request.method=="GET":
        return render_template("register.html")
    elif request.method=="POST":
        if not name:
            return apology("Must provide username", 400)
        if name and password:
            if any(user['username'] == name for user in users):
                return apology("Username already exists", 400)
            elif password != confirmation:
                return apology("Sorry, passwords do not match", 400)
            pwhash = generate_password_hash(password, method='scrypt', salt_length=16)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, pwhash)
            return redirect("/")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method=="POST":
        num = int(request.form.get("shares"))
        data = lookup(request.form.get("symbol"))
        if not data:
            return apology("Stock does not exist", 400)
        else:
            if num <0:
                return apology("Stock number lower than zero", 400)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
            stock = db.execute("SELECT * FROM stock WHERE id = ? AND stock_name = ?", session["user_id"], data["symbol"])
            if not stock:
                return apology("You don't own that stock", 400)
            stock_number = stock[0]["stock_number"]
            if stock_number < num:
                return apology("Sorry, insufficient shares number in your account", 400)
            else:
                ncash = cash + (data["price"]*num)
                if stock_number == num:
                    db.execute("DELETE FROM stock WHERE id = ? AND stock_name = ?", session["user_id"], data["symbol"])
                else:
                    db.execute("UPDATE stock SET stock_number = stock_number - ? WHERE id = ? AND stock_name = ?",num, session["user_id"], data["symbol"])
                db.execute("UPDATE users SET cash = ? WHERE id =?", ncash, session["user_id"])
                db.execute("INSERT INTO transactions (id, stock_name, shares, stock_price, type) VALUES (?, ?, ?, ?, ?)", session["user_id"], data["symbol"], num, data["price"], 'sell')
                return redirect("/")
    else:
        data =db.execute("SELECT * FROM stock WHERE id = ?", session["user_id"])
        stocks = []
        for row in data:
            name = lookup(row["stock_name"])
            stocks.append((name["name"], name["symbol"]))
        return render_template("sell.html", stocks=stocks)
