from flask import Flask, render_template, request, redirect, url_for, session, flash, escape
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
import sqlite3
import secrets
import bcrypt


app = Flask(__name__, root_path='C:/Users/User/python_playground')
app.secret_key = secrets.token_hex(16)

# Define the database connection and cursor objects
def get_db_conn():
    conn = sqlite3.connect("twitter_clone.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def get_db_cursor():
    return get_db_conn().cursor()

# Create the user table if it does not already exist
def create_user_table():
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL)''')
        conn.commit()

# Create the tweet table if it does not already exist
def create_tweet_table():
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tweets
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      tweet_text TEXT NOT NULL,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id))''')
        conn.commit()

# Create the follow table if it does not already exist
def create_follow_table():
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS follows
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      follower_id INTEGER NOT NULL,
                      FOREIGN KEY (user_id) REFERENCES users(id),
                      FOREIGN KEY (follower_id) REFERENCES users(id),
                      UNIQUE (user_id, follower_id))''')
        conn.commit()

# Initialize the database tables
def init_db():
    create_user_table()
    create_tweet_table()
    create_follow_table()

# Get the user ID of the currently logged-in user
def get_user_id():
    if "username" in session:
        username = session["username"]
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                return row["id"]

# Create a FlaskForm subclass for tweeting
class TweetForm(FlaskForm):
    tweet_text = TextAreaField("Tweet", validators=[DataRequired(), Length(max=280)])

# Create a FlaskForm subclass for signing up
class SignupForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])

# Create a FlaskForm subclass for logging in
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])

# Route for tweeting
@app.route("/tweet", methods=["GET", "POST"])
def add_tweet():
    if "username" not in session:
        flash("You must be logged in to tweet.")
        return redirect(url_for("login"))

    form = TweetForm()
    if form.validate_on_submit():
        tweet_text = form.tweet_text.data # validated tweet_text input
        user_id = get_user_id()
        if user_id:
            with get_db_conn() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO tweets (user_id, tweet_text) VALUES (?, ?)", (user_id, tweet_text))
                conn.commit()
            return redirect(url_for('home'))
    return render_template('tweet.html', form=form)

# database of users (in a real application, this would be stored in a database)
users = {}

@app.route("/")
def index():
    if "username" in session:
        return render_template("dashboard.html")
    else:
        return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode("utf-8")
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        users[username] = hashed_password
        session["username"] = username
        email = request.form['email']
        return redirect("/dashboard")
        
    else:
        return render_template('register.html')


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        if not username or not password:
            flash("Please enter a username and password.")
        elif get_user(username):
            flash("Username already taken. Please choose a different username.")
        else:
            create_user(username, password)
            flash("Account created successfully. Please log in.")
            return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")
        if username in users and bcrypt.checkpw(password, users[username]):
            session["username"] = username
            return redirect("/dashboard")
        else:
            return "Invalid username or password"
    else:
        return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.pop("username", None)
    return redirect("/")


@app.route("/dashboard")
def dashboard():
    if "username" in session:
        return render_template("dashboard.html")
    else:
        return redirect("/login")

@app.route('/profile/<username>')
def profile(username):
    # Add code to get the user's profile
    return render_template('profile.html', user=user)

@app.route('/new_tweet', methods=['GET', 'POST'])
def new_tweet():
    if request.method == 'POST':
        # Add code to create a new tweet
        return redirect(url_for('home'))
    return render_template('new_tweet.html')

@app.route('/')
def home():
    # Add code to get a list of tweets from all users
    return render_template('home.html', tweets=tweets)

@app.route("/tweet", methods=["POST"])
@login_required
def tweet():
    form = TweetForm()
    if form.validate_on_submit():
        tweet_text = form.tweet_text.data # validated tweet_text input
        user_id = get_user_id()
        if user_id:
            with get_db_conn() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO tweets (user_id, tweet_text) VALUES (?, ?)", (user_id, tweet_text))
                conn.commit()
                flash("Tweet posted successfully.")
        else:
            flash("User not found. Please log in.")
    else:
        flash("Invalid tweet. Please enter a tweet with at least 1 and at most 140 characters.")
    return redirect(url_for("dashboard"))

@app.route('/search')
def search():
    keyword = request.args.get('keyword')
    user = request.args.get('user')
    # Add code to search for tweets by keyword or user
    return render_template('search.html', tweets=tweets)


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(error):
    return render_template("500.html"), 500

if __name__ == '__main__':
    app.run(debug=True)
