from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import secrets
import string
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import current_user
from bson.objectid import ObjectId
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/project_management'
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return mongo.db.users.find_one({'_id': ObjectId(user_id)})

class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data

    def get_id(self):
        return str(self.user_data['_id'])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Generate OTP
        otp = generate_otp()

        # Send OTP via email
        msg = Message('Verify Your Email', sender='your_email@example.com', recipients=[email])
        msg.body = f'Your OTP for verification: {otp}'
        mail.send(msg)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {'username': username, 'email': email, 'password': hashed_password, 'otp': otp, 'verified': False}
        mongo.db.users.insert_one(user_data)
        flash('A verification OTP has been sent to your email. Please check and enter it below.', 'success')
        return redirect(url_for('verify'))
    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp = request.form['otp']
        user = mongo.db.users.find_one({'email': current_user.user_data['email'], 'otp': otp})
        if user:
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'verified': True}})
            flash('Your email has been verified. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = mongo.db.users.find_one({'email': email})
        if user and bcrypt.check_password_hash(user['password'], password) and user['verified']:
            login_user(User(user))
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email, password, or verify your email.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_tasks = mongo.db.tasks.find({'assignee_id': ObjectId(current_user.get_id())})
    return render_template('dashboard.html', tasks=user_tasks)

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        assignee_id = ObjectId(request.form['assignee'])
        due_date = request.form['due_date']
        task_data = {'title': title, 'description': description, 'assignee_id': assignee_id, 'due_date': due_date, 'status': 'To Do'}
        mongo.db.tasks.insert_one(task_data)
        flash('Task has been created!', 'success')
        return redirect(url_for('dashboard'))
    users = mongo.db.users.find()
    return render_template('create_task.html', users=users)

# Profile Form
class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

# Task Form
class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    assignee = SelectField('Assignee', coerce=ObjectId, validators=[DataRequired()])
    due_date = StringField('Due Date', validators=[DataRequired()])
    submit = SubmitField('Create Task')

# Route for profile page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        mongo.db.users.update_one({'_id': ObjectId(current_user.get_id())}, {'$set': {'username': form.username.data, 'email': form.email.data}})
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.user_data['username']
        form.email.data = current_user.user_data['email']
    return render_template('profile.html', form=form)

# Route to update task status
@app.route('/update_task_status/<task_id>/<status>', methods=['POST'])
@login_required
def update_task_status(task_id, status):
    # Update task status in the database
    mongo.db.tasks.update_one({'_id': ObjectId(task_id)}, {'$set': {'status': status}})
    flash('Task status updated successfully', 'success')
    return redirect(url_for('dashboard'))

# Route for task details page
@app.route('/task_details/<task_id>')
@login_required
def task_details(task_id):
    task = mongo.db.tasks.find_one({'_id': ObjectId(task_id)})
    return render_template('task_details.html', task=task)

# Import statement for sending email
from flask_mail import Message

# Function to send email notification
def send_email(recipient, subject, body):
    msg = Message(subject, sender='your_email@example.com', recipients=[recipient])
    msg.body = body
    mail.send(msg)

# Password Reset
# Route for password reset request
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = mongo.db.users.find_one({'email': form.email.data})
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

# Route for password reset
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# Task Search
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        search_query = request.form['search_query']
        # Perform search in tasks collection based on search_query
        tasks = mongo.db.tasks.find({'$text': {'$search': search_query}})
        return render_template('search_results.html', tasks=tasks)
    return render_template('search.html')

# Task Filtering and Sorting
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_tasks = mongo.db.tasks.find({'assignee_id': ObjectId(current_user.get_id())})
    if request.method == 'POST':
        # Get filter and sort parameters from form submission
        filter_criteria = request.form.get('filter_criteria')
        sort_criteria = request.form.get('sort_criteria')
        # Apply filtering and sorting based on parameters
        if filter_criteria == 'pending':
            user_tasks = user_tasks.filter({'status': 'To Do'})
        elif filter_criteria == 'completed':
            user_tasks = user_tasks.filter({'status': 'Done'})
        if sort_criteria == 'due_date_asc':
            user_tasks = user_tasks.sort('due_date', 1)
        elif sort_criteria == 'due_date_desc':
            user_tasks = user_tasks.sort('due_date', -1)
        # Render template with filtered and sorted tasks
        return render_template('dashboard.html', tasks=user_tasks)
    return render_template('dashboard.html', tasks=user_tasks)

# User Roles
class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

class UserRole(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'))

# Decorator to check user roles
def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.is_authenticated and \
               any(Role.query.filter_by(name=role).first() for role in roles):
                return f(*args, **kwargs)
            else:
                abort(403)  # Forbidden
        return wrapped
    return wrapper

# Task Comments
class TaskComment(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    task_id = db.Column(db.Integer(), db.ForeignKey('task.id'))
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    comment = db.Column(db.Text())
    timestamp = db.Column(db.DateTime(), default=datetime.utcnow)

# Route to add a comment to a task
@app.route('/add_comment/<task_id>', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.query.get_or_404(task_id)
    comment_text = request.form.get('comment')
    if comment_text:
        new_comment = TaskComment(comment=comment_text, user=current_user, task=task)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
    else:
        flash('Cannot add empty comment.', 'warning')
    return redirect(url_for('task_details', task_id=task_id))

# Task Attachments
class TaskAttachment(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    task_id = db.Column(db.Integer(), db.ForeignKey('task.id'))
    filename = db.Column(db.String(255))
    filepath = db.Column(db.String(255))

# Route to upload attachment to a task
@app.route('/upload_attachment/<task_id>', methods=['POST'])
@login_required
def upload_attachment(task_id):
    task = Task.query.get_or_404(task_id)
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            new_attachment = TaskAttachment(filename=filename, filepath=filepath, task=task)
            db.session.add(new_attachment)
            db.session.commit()
            flash('Attachment uploaded successfully.', 'success')
        else:
            flash('No file selected.', 'warning')
    return redirect(url_for('task_details', task_id=task_id))

# Data Validation (already implemented using FlaskForm and validators)

# Error Handling
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Pagination
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    user_tasks = Task.query.filter_by(assignee_id=current_user.id).paginate(page, per_page=10)
    return render_template('dashboard.html', tasks=user_tasks)

import unittest
from app import app, db

class FlaskTestCase(unittest.TestCase):

    # Ensure that Flask was set up correctly
    def test_index(self):
        tester = app.test_client(self)
        response = tester.get('/', content_type='html/text')
        self.assertEqual(response.status_code, 200)

    # Ensure that the login page loads correctly
    def test_login_page_loads(self):
        tester = app.test_client(self)
        response = tester.get('/login', content_type='html/text')
        self.assertTrue(b'Login' in response.data)

    # Ensure that the login behaves correctly given the correct credentials
    def test_correct_login(self):
        tester = app.test_client(self)
        response = tester.post('/login', data=dict(email="test@example.com", password="test"), follow_redirects=True)
        self.assertIn(b'Login Successful', response.data)

    # Ensure that the login behaves correctly given the incorrect credentials
    def test_incorrect_login(self):
        tester = app.test_client(self)
        response = tester.post('/login', data=dict(email="wrong@example.com", password="wrong"), follow_redirects=True)
        self.assertIn(b'Invalid email or password', response.data)

    # Add more test cases as needed

# Route for deleting a team
@app.route('/delete_team/<team_id>', methods=['POST'])
@login_required
def delete_team(team_id):
    mongo.db.teams.delete_one({'_id': ObjectId(team_id)})
    flash('Team has been deleted!', 'success')
    return redirect(url_for('team_management'))

@app.route('/team_management')
@login_required
def team_management():
    teams = mongo.db.teams.find()
    return render_template('team_management.html', teams=teams)

def generate_otp(length=6):
    characters = string.digits
    return ''.join(secrets.choice(characters) for i in range(length))

if __name__ == '__main__':
    app.run(debug=True)
