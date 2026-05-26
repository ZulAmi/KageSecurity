"""
Deliberately vulnerable Flask app for testing KageSec scanner modules.
DO NOT deploy this anywhere — for local testing only.
"""
from flask import Flask, request, redirect, make_response
import sqlite3
import os

app = Flask(__name__)

# In-memory SQLite with some data
def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    db.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com')")
    db.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com')")
    return db


@app.route("/")
def index():
    return """
    <html><body>
    <h1>KageSec Test App</h1>
    <ul>
      <li><a href="/search">Search (XSS)</a></li>
      <li><a href="/user?id=1">User lookup (SQLi)</a></li>
      <li><a href="/redirect?next=/">Redirect (Open Redirect)</a></li>
      <li><a href="/fetch?url=http://example.com">Fetch URL (SSRF)</a></li>
    </ul>
    </body></html>
    """


@app.route("/search")
def search():
    # Vulnerable: reflects query param directly into HTML
    q = request.args.get("q", "")
    return f"""
    <html><body>
    <form method="get" action="/search">
      <input name="q" value="{q}" />
      <button type="submit">Search</button>
    </form>
    <p>Results for: {q}</p>
    </body></html>
    """


@app.route("/user")
def user():
    # Vulnerable: raw user input in SQL query
    user_id = request.args.get("id", "1")
    try:
        db = get_db()
        row = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
        result = str(row) if row else "Not found"
    except Exception as e:
        result = f"Database error: {e}"
    return f"""
    <html><body>
    <form method="get" action="/user">
      <input name="id" value="{user_id}" />
      <button type="submit">Look up user</button>
    </form>
    <p>{result}</p>
    </body></html>
    """


@app.route("/redirect")
def redir():
    # Vulnerable: redirects to any URL in ?next=
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/fetch")
def fetch():
    # Vulnerable: fetches any URL from ?url= param (SSRF)
    url = request.args.get("url", "")
    if url:
        try:
            import httpx
            resp = httpx.get(url, timeout=3)
            body = resp.text[:500]
        except Exception as e:
            body = f"Error: {e}"
    else:
        body = ""
    return f"""
    <html><body>
    <form method="get" action="/fetch">
      <input name="url" value="{url}" />
      <button type="submit">Fetch</button>
    </form>
    <pre>{body}</pre>
    </body></html>
    """


if __name__ == "__main__":
    app.run(port=8888, debug=False)
