from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

#This is to set up the database with password logins
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assignment3.db'
app.config['SECRET_KEY'] = '992885fd8f9aedbb18a511ed05eef0793bce067f444de4ac6163d3b95b55473b'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



#include ALL database setups here to keep organized. follow the same format for any of the database and should work
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)#now its just defining the collums with things like char limit, primary key setting, unique etc
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    firstn = db.Column(db.String(50), nullable=False) #thats a long name
    lastn = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    role = db.Column(db.String(10), nullable=False)  
    grades = db.relationship('Grade', backref='student', lazy=True)#backref if you need to go back and forth in relation ship instead of one way

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignment1 = db.Column(db.Float, nullable=False, default=0)  #Could also make nullable and have defult as null but zero is prob better
    assignment2 = db.Column(db.Float, nullable=False, default=0)
    assignment3 = db.Column(db.Float, nullable=False, default=0)
    midterm = db.Column(db.Float, nullable=False, default=0)
    lab = db.Column(db.Float, nullable=False, default=0)
    final_exam = db.Column(db.Float, nullable=False, default=0)

class RemarkRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    grade_id = db.Column(db.Integer, db.ForeignKey('grade.id'), nullable=False)
    assessment_type = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(10), default="Pending")
    student = db.relationship('User', backref='remarks')
    grade = db.relationship('Grade', backref='remarks')

class Feedback(db.Model):  #Do we want to limit the size of feedback in the database?
    id = db.Column(db.Integer, primary_key=True)
    instructor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes_teaching = db.Column(db.Text, nullable=False)
    improve_teaching = db.Column(db.Text, nullable=False)
    likes_labs = db.Column(db.Text, nullable=False)
    improve_labs = db.Column(db.Text, nullable=False)
    reviewed = db.Column(db.Boolean, default=False)
    instructor = db.relationship('User', backref='feedback_received')


#Again, heres all the routes please keep them all here. try give good name too, this is more complicated then html to find things
@app.route('/home')
def index():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST']) #nice
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstn = request.form['FirstName'] 
        lastn = request.form.get('LastName', '') 
        email = request.form['email']
        role = request.form['role']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if not username or not password or not firstn or not email or not role:
            flash('Fill all required fields.', 'danger') #flash is easiest way to give user message on an input
            return redirect(url_for('register'))
        
        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('Username/Email already in database', 'danger')
            return redirect(url_for('register'))
    
        new_user = User(username=username, password=hashed_password, firstn=firstn, lastn=lastn, email=email, role=role) #so we can add to db
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/grades')
@login_required
def grades():
    if current_user.role == 'student':
        student_grades = Grade.query.filter_by(student_id=current_user.id).first()
        remark_requests = RemarkRequest.query.filter_by(student_id=current_user.id).all()
        
        # Ensure we have a grades record for the student
        if not student_grades:
            student_grades = Grade(student_id=current_user.id)
            db.session.add(student_grades)
            db.session.commit()
            
        return render_template('grades.html', 
                             student_grades=student_grades, 
                             remark_requests=remark_requests,
                             current_user=current_user)
    
    elif current_user.role == 'instructor':
        all_grades = Grade.query.all()
        students = User.query.filter_by(role='student').all()
        remark_requests = RemarkRequest.query.all()
        return render_template('grades.html', 
                             all_grades=all_grades, 
                             students=students, 
                             remark_requests=remark_requests,
                             current_user=current_user)
    else:
        flash("Not alllowed!", "danger")
        return redirect(url_for('index'))

@app.route('/submit_remark_request', methods=['POST'])
@login_required  #IMPORTANT you need this when logins required
def submit_remark_request():
    if current_user.role != 'student':  #I know this dosint hurt to have this but is it even possible for a non student to submit remark req
        flash('Not allowed!', 'danger')
        return redirect(url_for('index'))
    
    grade_id = request.form.get('grade_id')
    assessment_type = request.form.get('assessment_type')
    reason = request.form.get('reason')
    
    if not all([grade_id, assessment_type, reason]):
        flash('Fill all required fields.', 'danger')
        return redirect(url_for('grades'))
    
    grade = Grade.query.get(grade_id)
    if not grade or grade.student_id != current_user.id:
        flash('Grade invalid', 'danger')
        return redirect(url_for('grades'))
    
    existing_request = RemarkRequest.query.filter_by(
        student_id=current_user.id,
        grade_id=grade_id,
        assessment_type=assessment_type
    ).first()
    
    if existing_request:
        flash('Request already exists', 'danger')
        return redirect(url_for('grades'))
    
    new_request = RemarkRequest(
        student_id=current_user.id,
        grade_id=grade_id,
        assessment_type=assessment_type,
        reason=reason,
        status='Pending'
    )
    
    db.session.add(new_request)
    db.session.commit()
    
    flash('Remark request submitted successfully!', 'success')
    return redirect(url_for('grades'))



@app.route('/update_remark_status/<int:request_id>/<status>')
@login_required
def update_remark_status(request_id, status):
    if current_user.role != 'instructor':
        flash('Not allowed', 'danger')
        return redirect(url_for('index'))
    
    remark_request = RemarkRequest.query.get(request_id)
    if not remark_request:
        flash('Request not found', 'danger')
        return redirect(url_for('grades'))
    
    remark_request.status = status
    db.session.commit()
    
    flash(f'Status: {status}!', 'success')
    
    # if they approve we just redirect them right to the enter marks if they decline then do nothing. this should be far simpiler then bring them
    # directly to change the exact mark
    if status == 'Approved':
        return redirect(url_for('enter_marks'))
    return redirect(url_for('grades'))


@app.route('/enter_marks', methods=['GET', 'POST'])
@login_required
def enter_marks():
    if current_user.role != 'instructor':
        flash('Not allowed', 'danger')
        return redirect(url_for('index'))
    
    students = User.query.filter_by(role='student').all()
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        assessment_type = request.form['assessment_type']
        mark = float(request.form['mark'])
        
        grade = Grade.query.filter_by(student_id=student_id).first()
        if not grade:
            grade = Grade(student_id=student_id)
            db.session.add(grade)
        
        setattr(grade, assessment_type, mark)
        db.session.commit()
        flash('Mark updated successfully', 'success')
        return redirect(url_for('grades'))
    
    return render_template('enter_marks.html', students=students)


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check credentials', 'danger')
    return render_template('login.html')

#added a logout, seems like something we should have even though its not specified
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if current_user.role != 'student':
        flash('Only students can submit feedback', 'danger')
        return redirect(url_for('index'))
    
    instructors = User.query.filter_by(role='instructor').all()
    
    if request.method == 'POST':
        instructor_id = request.form['instructor_id']
        instructor = User.query.filter_by(id=instructor_id, role='instructor').first()
        if not instructor:
            flash('not an instructor', 'danger')
            return redirect(url_for('feedback'))
        
        new_feedback = Feedback(
            instructor_id=instructor_id,
            likes_teaching=request.form['likes_teaching'],
            improve_teaching=request.form['improve_teaching'],
            likes_labs=request.form['likes_labs'],
            improve_labs=request.form['improve_labs']
        )
        
        db.session.add(new_feedback)
        db.session.commit()
        
        flash('Your feedback has been submitted successfully', 'success')
        return redirect(url_for('feedback'))
    
    return render_template('feedback.html', instructors=instructors)



@app.route('/view_feedback', methods=['GET', 'POST'])
@login_required
def view_feedback():
    if current_user.role != 'instructor':
        flash('not instructor', 'danger')
        return redirect(url_for('index'))
    
    filter_type = request.args.get('filter', 'all')
    
    if request.method == 'POST':
        feedback_id = request.form.get('feedback_id')
        action = request.form.get('action')
        
        if action == 'mark_reviewed':
            feedback = Feedback.query.get(feedback_id)
            if feedback and feedback.instructor_id == current_user.id:
                feedback.reviewed = True
                db.session.commit()
                flash('feedback has been reviewed', 'success')
    
    base_query = Feedback.query.filter_by(instructor_id=current_user.id)
    
    if filter_type == 'unreviewed':
        feedback_list = base_query.filter_by(reviewed=False).all()
    elif filter_type == 'reviewed':
        feedback_list = base_query.filter_by(reviewed=True).all()
    else:
        feedback_list = base_query.all()
    
    return render_template('view_feedback.html', feedback_list=feedback_list, filter_type=filter_type)


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)



