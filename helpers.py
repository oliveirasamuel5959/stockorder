import csv
import datetime
import pytz
import requests
import subprocess
import urllib
import uuid

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Prepare API request
    symbol = symbol.upper()
    end = datetime.datetime.now(pytz.timezone("US/Eastern"))
    start = end - datetime.timedelta(days=7)

    # Yahoo Finance API
    url = (
        #f"https://query1.finance.yahoo.com/v7/finance/download/{urllib.parse.quote_plus(symbol)}"
        f"https://api.iex.cloud/v1/data/core/quote/{urllib.parse.quote_plus(symbol)}?token=pk_6e8c5587742e440ca9ab50bc7f7927a0"
        #f"?period1={int(start.timestamp())}"
        #f"&period2={int(end.timestamp())}"
        #f"&interval=1d&events=history&includeAdjustedClose=true"
    )

    # Query API
    try:
        response = requests.get(url, cookies={"session": str(uuid.uuid4())}, headers={"User-Agent": "python-requests", "Accept": "*/*"})
        response.raise_for_status()

        # CSV header: Date,Open,High,Low,Close,Adj Close,Volume
        json_response = response.json()
        price = json_response[0]["latestPrice"]
        name = json_response[0]["companyName"]
        company_symbol = json_response[0]["symbol"]
        return {
            "name": name,
            "price": price,
            "symbol": company_symbol
        }
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        return None


def usd(value):
    """Format value as USD."""
    if value is None:
        return f"${0:,.2f}"
    else:
        return f"${value:,.2f}"

