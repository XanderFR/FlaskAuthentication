from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# Configure Flask-Login Login Manager
# Has the code that lets app and Flask-Login work together
loginManager = LoginManager()
loginManager.init_app(app)


# Create user_loader callback
# Reloads the user object from user ID stored in the session
@loginManager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB with the UserMixin
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    # Page modified if user is authenticated
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        # Find a user through email if already in database
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:  # If user already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        # Hashing and salting the user's password to make it more complex
        hashAndSaltedPassword = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )

        # Prepare new user information bundle from form data
        newUser = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hashAndSaltedPassword
        )

        # Add newUser data to database
        db.session.add(newUser)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(newUser)

        # Can redirect() and get name from the current_user
        return redirect(url_for("secrets"))
    # Page modified if user is authenticated
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user through the email address
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        # If email non-existent or incorrect password
        if not user:
            flash("Email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:  # Email and password both work
            login_user(user)
            return redirect(url_for('secrets'))
    # Page modified if user is authenticated
    return render_template("login.html", logged_in=current_user.is_authenticated)


# Secrets page only accessible by logged-in users
@app.route('/secrets')
@login_required
def secrets():
    # Secrets page presents current user name
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    # The Logout function
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
def download():
    # Prepare the file download page
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
