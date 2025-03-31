from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pets.db'
# Admin credentials stored in configuration
app.config['ADMIN_USERNAME'] = 'Admin_user@gmail.com'
app.config['ADMIN_PASSWORD'] = 'Admin@123'
db = SQLAlchemy(app)

# Database model for users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Database model for contact messages
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    message = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('pet.html')

@app.route('/signup', methods=['POST'])
def signup():
    first_name = request.form.get('first-name')
    last_name = request.form.get('last-name')
    email = request.form.get('email')
    password = request.form.get('password')

    # Hash the password securely
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    flash('Account created successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        flash('Login successful!', 'success')
        return redirect(url_for('home'))
    else:
        flash('Login failed. Check your email and password.', 'danger')
        return redirect(url_for('home'))

@app.route('/submit-form', methods=['POST'])
def submit_form():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    message = request.form.get('message')

    new_message = ContactMessage(name=name, email=email, phone=phone, message=message)
    db.session.add(new_message)
    db.session.commit()
    flash('Message sent successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        # Use strip() to remove any leading/trailing whitespace
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Debugging: print the credentials received (remove in production)
        print("Attempted Admin Login:")
        print(f"Username: '{username}'")
        print(f"Password: '{password}'")

        # Compare credentials against configuration values
        if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Username/Password is Incorrect', 'danger')
            return redirect(url_for('admin'))
    return render_template("admin_login.html")

@app.route('/admin/dashboard')
def admin_dashboard():
    # Debugging: print(session) to check if admin_logged_in is set
    print("Current session:", session)
    if not session.get('admin_logged_in'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('admin'))
    users_data = User.query.all()
    return render_template("admin_dashboard.html", users=users_data)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
