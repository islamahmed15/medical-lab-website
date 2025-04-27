import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_

# Create instance folder automatically
instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(instance_path, exist_ok=True)

# Initialize Flask app
app = Flask(__name__, instance_path=instance_path)

# Correct absolute path to the database
db_path = os.path.join(instance_path, 'lab.db')

# Flask configuration
app.config['SECRET_KEY'] = 'a8f9e9b0a3c14e29a6d42f8d931f7cfa4be67829b5761a5e9f17c3d2e456c891'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'Uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Define the Result model
class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='results')

# Load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# File extension validation
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        existing_username = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
        if existing_username:
            flash('Username already taken.', 'warning')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(email=email, username=username, password=hashed_password, is_admin=False)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can log in now.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Email not found." if user is None else "Incorrect password.", "danger")
            return render_template('login.html', email=email)

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    results = Result.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', results=results)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current-password']
        new_password = request.form['new-password']
        confirm_new_password = request.form['confirm-new-password']

        # Validate current password
        if not check_password_hash(current_user.password, current_password):
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('change_password'))

        # Validate new password requirements
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#_])[A-Za-z\d@$!%*?&#_]{8,}$'
        import re
        if not re.match(password_regex, new_password):
            flash('New password must include at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&#_).', 'danger')
            return redirect(url_for('change_password'))

        # Check if new passwords match
        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        # Update password
        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    
    search_query = request.args.get('search', '').strip()
    selected_user_id = None
    results_user = None
    users = []
    results = []

    if search_query:
        try:
            # Try converting search_query to an integer for ID search
            search_id = int(search_query)
            users = User.query.filter(or_(User.id == search_id, User.username.ilike(f'%{search_query}%'))).filter_by(is_admin=False).all()
        except ValueError:
            # If not an integer, search by username only
            users = User.query.filter(User.username.ilike(f'%{search_query}%')).filter_by(is_admin=False).all()
        
        # If exactly one user is found, filter results and pre-select the user
        if len(users) == 1:
            selected_user_id = users[0].id
            results = Result.query.filter_by(user_id=selected_user_id).all()
            results_user = users[0]
        else:
            results = []  # No results if multiple or no users found
    else:
        users = User.query.filter_by(is_admin=False).all()
        results = Result.query.all()  # Show all results if no search
    
    if request.method == 'POST' and 'file' in request.files:
        user_id = request.form['user_id']
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            result = Result(filename=filename, user_id=user_id)
            db.session.add(result)
            db.session.commit()
            flash('PDF uploaded successfully.', 'success')
        else:
            flash('Invalid file. Only PDFs are allowed.', 'danger')
        # Redirect with search query to maintain state
        return redirect(url_for('admin_dashboard', search=search_query))
    
    return render_template(
        'admin.html',
        users=users,
        results=results,
        search_query=search_query,
        selected_user_id=selected_user_id,
        results_user=results_user
    )

@app.route('/admin/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot reset password for admin users.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        new_password = request.form['new-password']
        confirm_new_password = request.form['confirm-new-password']
        
        # Validate new password requirements
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#_])[A-Za-z\d@$!%*?&#_]{8,}$'
        import re
        if not re.match(password_regex, new_password):
            flash('New password must include at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&#_).', 'danger')
            return redirect(url_for('reset_password', user_id=user_id))
        
        # Check if passwords match
        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('reset_password', user_id=user_id))
        
        # Update password
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash(f'Password for {user.username} (ID: {user.id}) reset successfully.', 'success')
        return redirect(url_for('admin_dashboard', search=user.id))
    
    return render_template('admin_reset_password.html', user=user)

@app.route('/delete_result/<int:result_id>', methods=['GET'])
@login_required
def delete_result(result_id):
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    
    result = Result.query.get_or_404(result_id)
    try:
        # Delete the file from storage
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], result.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        # Delete the result from the database
        db.session.delete(result)
        db.session.commit()
        flash('Result deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting result: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    result = Result.query.filter_by(filename=filename).first()
    if not result:
        flash('File not found.', 'danger')
        return redirect(url_for('dashboard'))
    if result.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to download this file.', 'danger')
        return redirect(url_for('dashboard'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/history')
@login_required
def history():
    results = Result.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', results=results)

@app.route('/locations')
def locations():
    return render_template('locations.html')

# Initialize database
with app.app_context():
    db.create_all()

# Run the app
if __name__ == '__main__':
    app.run(debug=True)