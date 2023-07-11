import os
import datetime
import pytz
import mysql.connector
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

config = {
    "DEBUG": True # run app in debug mode
}

# Configure application
app = Flask(__name__)

app.config.from_mapping(config)

# reload html files automatic when changes are made in the server
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
conn = mysql.connector.connect(
    host= "localhost",
    username="root",
    password="password",
    database="finance",
    port="3306"
)

db = conn.cursor()
# sql_insert_into = "INSERT INTO users (id, username, hash, cash) VALUES ('0', 'Samuel', '123456', '10');"


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
    db.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    row_users = db.fetchall()

    """ Select the portifolio content of the user current log-in """
    db.execute("SELECT * FROM portifolio WHERE username = %s", (session["user_name"],))
    row_portifolio = db.fetchall()

    """ Sum the user total value invested """
    db.execute("SELECT SUM(Total) FROM portifolio WHERE username = %s", (session["user_name"],))
    row_sum = db.fetchall()
    
    return render_template(
            "index.html", 
            portifolio=row_portifolio, 
            total_cash=usd(row_sum[0][0]), 
            username=session["user_name"],
            cash= usd(row_users[0][3]))


@app.route("/cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":

        cash_value = request.form.get("cash")
        if not cash_value:
            return apology("Enter a value", 403)
        
        db.execute("SELECT * FROM users WHERE id = (%s)", (session["user_id"],))
        row_users = db.fetchall()

        sum_cash = int(cash_value) + row_users[0][3]

        db.execute("UPDATE users SET cash = (%s) WHERE id = (%s)", (sum_cash, session["user_id"]))
        conn.commit()

        return redirect("/")

    else:
        return render_template("cash.html")
    

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        stock_symbol = request.form.get("symbol")
        num_shares = request.form.get("shares")

        num_shares = int(num_shares)

        if type(num_shares) is str:
            return apology("shares need to be integer value", 403)

        if not stock_symbol:
            return apology("You need to enter a symbol", 403)
        
        if num_shares <= 0:
            return apology("Minimum share you can buy is one", 403)

        stock = lookup(stock_symbol)

        print(stock)

        if stock is None:
            return apology("The stock symbol do not exist", 403)
        
        db.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],) )
        row_users = db.fetchall()

        db.execute("SELECT * FROM portifolio WHERE Username=%s AND Symbol=%s", (session["user_name"], stock['symbol']) )
        row_portifolio = db.fetchall()

        total = num_shares*stock['price']

        if total >= row_users[0][3]:
            return apology("You don't have enough money!", 403)

        if len(row_portifolio) != 0 and stock['symbol'] == row_portifolio[0][2]:
            price_payed = row_users[0][3] - total
            db.execute("UPDATE users SET cash = %s WHERE id = %s", (price_payed, session["user_id"]))
            sql_insert = "UPDATE portifolio SET shareQtd=%s, sharePrice=%s, Total=%s WHERE Username=%s AND Symbol=%s"
            sql_values = (row_portifolio[0][3]+num_shares, stock['price'], row_portifolio[0][5]+total, session['user_name'], stock['symbol'])
            db.execute(sql_insert, sql_values)
            conn.commit()
        else:
            price_payed = row_users[0][3] - total
            db.execute("UPDATE users SET cash = %s WHERE id = %s", (price_payed, session["user_id"]))
            sql_insert = "INSERT INTO portifolio (Username, companyName, Symbol, shareQtd, sharePrice, Total) VALUES (%s, %s, %s, %s, %s, %s)"
            sql_values = (row_users[0][1], stock['name'], stock['symbol'], num_shares, stock['price'], total)
            db.execute(sql_insert, sql_values)
            conn.commit()

        time = datetime.datetime.now(pytz.timezone("America/Sao_Paulo")).replace(microsecond=0)


        db.execute("INSERT INTO transactions (Type,Symbol,Shares,Price,Date,Username) VALUES (%s,%s,%s,%s,%s,%s)", 
                    ('Buyed', stock['symbol'], num_shares, stock['price'], time, session["user_name"]))
        conn.commit()

        return redirect("/")
        
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    db.execute("SELECT * FROM transactions WHERE Username=%s", (session["user_name"],))
    row_transactions = db.fetchall()

    return render_template("history.html", transactions=row_transactions)


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
        username = request.form.get("username")
        password = request.form.get("password")

        db.execute("SELECT * FROM users WHERE username = %s", (username,))
        rows = db.fetchall()

        # Ensure username exists and password is correct
        if len(rows) == 0 or not check_password_hash(rows[0][2], password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]
        session["user_name"] = rows[0][1]

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
    if request.method == "POST":

        stock_symbol = request.form.get("symbol")
        if not stock_symbol:
            return apology("You need to enter a symbol", 403)
        
        stock = lookup(stock_symbol)

        if stock is None:
            return apology("The stock symbol do not exist", 403)

        return render_template("quoted.html", stock_quoted=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        # ensure username was submmited
        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        # ensure password was submmited
        if not request.form.get("password"):
            return apology("must provide password", 403)
        
        # confirm password
        if not request.form.get("confirm_password"):
            return apology("must confirm the password", 403)
        
        # ensure that the passwords matches
        if request.form.get("password") != request.form.get("confirm_password"):
            return apology("password do not macth!", 403)

        # ensure that the username do not alreay exisits in the database
        db.execute("SELECT * FROM users WHERE username = %s", (request.form.get("username"),))
        row_user = db.fetchall()

        if len(row_user) != 0:
            return apology("Sorry, username already taken", 403)
        
        # Generate password hash for security
        password_hash = generate_password_hash(request.form.get("confirm_password"))


        # add user registration to the database
        user_name = request.form.get("username")
        sql = "INSERT INTO users (username, password, cash) VALUES (%s, %s, %s)"
        val = (user_name, password_hash, '0')
        db.execute(sql, val)
        conn.commit()

        return redirect("/")
    
    else:
        return render_template("register.html")
    #return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_shares = {}
    """ return the user row from portifolio table """
    db.execute("SELECT * FROM portifolio WHERE Username = %s", (session["user_name"],))
    row_portifolio = db.fetchall()

    if request.method == "POST":

        """ Check for user correct symbol input """
        if not request.form.get("symbol"):
            return apology("You need to enter a symbol", 403)
        
        """ Check for user correct shares input """
        if not request.form.get("shares"):
            return apology("Minimum share you can sell is one", 403)

        """ return the user row from users table """
        db.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
        row_users = db.fetchall()

        """ return the user row from portifolio table """
        db.execute("SELECT * FROM portifolio WHERE Username=%s AND Symbol=%s", (session["user_name"], request.form.get("symbol")))
        row_portifolio = db.fetchall()

        """ check if user has minimum shares to sell """
        if int(request.form.get("shares")) > row_portifolio[0][3]:
            return apology("You do not have enough share to sell", 403)

        """ Get the stock current price to sell """
        stock = lookup(request.form.get("symbol"))

        new_sharesQtd = row_portifolio[0][3] - int(request.form.get("shares"))
        new_total = stock['price']*new_sharesQtd

        """ Delete stock from database table if there is no more shares left """
        if new_sharesQtd <= 0:
            db.execute("DELETE FROM portifolio WHERE Username=%s AND Symbol=%s", (session["user_name"], request.form.get('symbol')))
            conn.commit()

        db.execute("UPDATE portifolio SET shareQtd=%s, Total=%s WHERE Username=%s AND Symbol=%s", (new_sharesQtd, new_total, session["user_name"], stock['symbol']))
        db.execute("UPDATE users SET cash=%s WHERE id=%s", (row_users[0][3]+stock['price']*int(request.form.get("shares")), session["user_id"]))
        conn.commit()

        time = datetime.datetime.now(pytz.timezone("America/Sao_Paulo")).replace(microsecond=0)

        db.execute("INSERT INTO transactions (Type,Symbol,Shares,Price,Date,Username) VALUES (%s,%s,%s,%s,%s,%s)", 
                    ('Sold', stock['symbol'], int(request.form.get("shares")), stock['price'], time, session["user_name"]))
        conn.commit()

        return redirect("/")

    else:
        return render_template("sell.html", shares=row_portifolio)


if __name__ == '__main__':
    app.run(debug=True)
