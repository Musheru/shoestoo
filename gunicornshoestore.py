import os
from functools import wraps
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ------------------- APP CONFIG -------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///shoes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('FLASK_SECRET', 'supersecretkey')

# File upload settings
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'shoe_images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ------------------- MODELS -------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Shoe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    price = db.Column(db.Float, nullable=False, index=True)
    description = db.Column(db.String(500))
    quantity = db.Column(db.Integer, default=0)
    image_filename = db.Column(db.String(200))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    items = db.Column(db.String(2000))
    total = db.Column(db.Float)

# ------------------- HELPERS -------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Login required.", "error")
            return redirect(url_for('login'))
        user = User.query.filter_by(username=session['username']).first()
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def current_user():
    if 'username' not in session:
        return None
    return User.query.filter_by(username=session['username']).first()

# ------------------- ROUTES -------------------
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('shoes'))
    return render_template_string("""<h1>Welcome to Nairobi Best Thrifts</h1>
<p><a href="{{ url_for('signup') }}">Sign Up</a> | <a href="{{ url_for('login') }}">Login</a></p>""")

# ----- signup/login/logout -----
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash("Provide username and password.", "error")
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return redirect(url_for('signup'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created! Log in.", "success")
        return redirect(url_for('login'))
    return render_template_string("""<h2>Sign Up</h2><form method="POST">
Username: <input name="username" required><br>Password: <input name="password" type="password" required><br>
<button type="submit">Register</button></form>""")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            flash(f"Welcome {username}!", "success")
            return redirect(url_for('shoes'))
        flash("Invalid username or password.", "error")
        return redirect(url_for('login'))
    return render_template_string("""<h2>Login</h2><form method="POST">
Username: <input name="username" required><br>Password: <input name="password" type="password" required><br>
<button type="submit">Login</button></form>""")

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out.", "success")
    return redirect(url_for('home'))

# ----- shoes listing -----
@app.route('/shoes')
def shoes():
    if 'username' not in session:
        flash("Please log in.", "error")
        return redirect(url_for('login'))

    q = request.args.get('q','').strip()
    sort = request.args.get('sort','name_asc')
    page = request.args.get('page',1,type=int)
    per_page = max(1,min(request.args.get('per_page',6,type=int),50))
    query = Shoe.query
    if q:
        query = query.filter(Shoe.name.ilike(f"%{q}%"))
    if sort=='name_asc': query=query.order_by(Shoe.name.asc())
    elif sort=='name_desc': query=query.order_by(Shoe.name.desc())
    elif sort=='price_asc': query=query.order_by(Shoe.price.asc())
    elif sort=='price_desc': query=query.order_by(Shoe.price.desc())
    else: query=query.order_by(Shoe.name.asc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    shoes = pagination.items
    user = current_user()
    return render_template_string("<h1>Shoes</h1>{{shoes}}", shoes=shoes)

# ------------------- DATABASE SETUP -------------------
def setup_database():
    with app.app_context():
        db.create_all()
        if Shoe.query.count()==0:
            db.session.add_all([
                Shoe(name="Nike Air Max", price=120.99, description="Classic Nike shoe", quantity=10),
                Shoe(name="Adidas Ultraboost", price=139.49, description="High performance running shoe", quantity=7),
            ])
            db.session.commit()
        if User.query.filter_by(role='admin').count()==0:
            admin = User(username='admin')
            admin.set_password('admin123')
            admin.role='admin'
            db.session.add(admin)
            db.session.commit()
            print("Created default admin")

# ------------------- NOTE -------------------
# Gunicorn will run this app: gunicorn shoestore4:app
# No need for app.run() in production
# Optional: call setup_database() locally once if needed

