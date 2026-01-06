import string
import random
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'awdjklajwdiwaiojdiqojdwkqjdklajdioqjdioqdjasnfhrenfri'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///christmas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

def generate_group_code():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(6))

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    join_code = db.Column(db.String(10), unique=True, nullable=False)
    users = db.relationship('User', backref='group', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    display_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    wishes = db.relationship('Wish', foreign_keys='Wish.user_id', backref='owner', lazy=True)

class Wish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    url = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reserved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('dashboard'))
    else:
        flash('Špatné jméno nebo heslo.', 'error')
        return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    display_name = request.form.get('display_name')
    password = request.form.get('password')
    reg_type = request.form.get('reg_type')
    
    if User.query.filter_by(username=username).first():
        flash('Uživatel s tímto přihlašovacím jménem/id již existuje.', 'error')
        return redirect(url_for('index'))

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    
    if reg_type == 'create':
        group_name = request.form.get('group_name')
        if not group_name:
            flash('Zadej název rodiny.', 'error')
            return redirect(url_for('index'))
        code = generate_group_code()
        while Group.query.filter_by(join_code=code).first():
            code = generate_group_code()
        new_group = Group(name=group_name, join_code=code)
        db.session.add(new_group)
        db.session.commit()
        new_user = User(username=username, display_name=display_name, password=hashed_pw, group=new_group)
        
    elif reg_type == 'join':
        join_code = request.form.get('join_code').upper()
        group = Group.query.filter_by(join_code=join_code).first()
        if not group:
            flash('Neplatný kód rodiny.', 'error')
            return redirect(url_for('index'))
        new_user = User(username=username, display_name=display_name, password=hashed_pw, group=group)
    else:
        return redirect(url_for('index'))

    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    group_users = User.query.filter_by(group_id=current_user.group_id).all()
    return render_template('dashboard.html', users=group_users)

@app.route('/add_wish', methods=['POST'])
@login_required
def add_wish():
    text = request.form.get('text')
    url = request.form.get('url')
    if text:
        new_wish = Wish(text=text, url=url, owner=current_user)
        db.session.add(new_wish)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_wish/<int:wish_id>')
@login_required
def delete_wish(wish_id):
    wish = Wish.query.get_or_404(wish_id)
    if wish.owner == current_user:
        db.session.delete(wish)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/toggle_reserve/<int:wish_id>')
@login_required
def toggle_reserve(wish_id):
    wish = Wish.query.get_or_404(wish_id)
    if wish.owner.group_id != current_user.group_id:
        return redirect(url_for('dashboard'))
    if wish.owner == current_user:
        return redirect(url_for('dashboard'))
    if wish.reserved_by is None:
        wish.reserved_by = current_user.id
        db.session.commit()
    elif wish.reserved_by == current_user.id:
        wish.reserved_by = None
        db.session.commit()
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/my_reservations')
@login_required
def my_reservations():
    reservations = Wish.query.filter_by(reserved_by=current_user.id).all()
    return render_template('reservations.html', wishes=reservations)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
