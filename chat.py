from flask import Flask, request, jsonify, send_file, url_for
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import allowed_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pptx', 'docx', 'xlsx'}
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'ops' or 'client'
    is_verified = db.Column(db.Boolean, default=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.now())

# Utility Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/ops/login', methods=['POST'])
def ops_login():
    data = request.json
    user = User.query.filter_by(username=data['username'], role='ops').first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/ops/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    if current_user['role'] != 'ops':
        return jsonify({'message': 'Unauthorized'}), 403

    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        new_file = File(filename=filename, uploaded_by=current_user['id'])
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully'}), 201
    else:
        return jsonify({'message': 'File type not allowed'}), 400

@app.route('/client/signup', methods=['POST'])
def client_signup():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, role='client')
    db.session.add(new_user)
    db.session.commit()

    token = serializer.dumps(data['email'], salt='email-confirm')
    verification_link = url_for('verify_email', token=token, _external=True)
    return jsonify({'verification-link': verification_link}), 201

@app.route('/client/verify', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
            return jsonify({'message': 'Email verified successfully'}), 200
        return jsonify({'message': 'Invalid token'}), 400
    except (BadSignature, SignatureExpired):
        return jsonify({'message': 'Invalid or expired token'}), 400

@app.route('/client/login', methods=['POST'])
def client_login():
    data = request.json
    user = User.query.filter_by(username=data['username'], role='client').first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        if not user.is_verified:
            return jsonify({'message': 'Email not verified'}), 403
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/client/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = get_jwt_identity()
    if current_user['role'] != 'client':
        return jsonify({'message': 'Unauthorized'}), 403

    files = File.query.all()
    file_list = [{'id': file.id, 'filename': file.filename, 'uploaded_at': file.uploaded_at} for file in files]
    return jsonify({'files': file_list}), 200

@app.route('/client/download/<int:file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'client':
        return jsonify({'message': 'Unauthorized'}), 403

    file = File.query.get(file_id)
    if not file:
        return jsonify({'message': 'File not found'}), 404

    token = serializer.dumps(file.filename, salt='file-download')
    download_link = url_for('secure_download', token=token, _external=True)
    return jsonify({'download-link': download_link, 'message': 'success'}), 200

@app.route('/secure-download/<token>', methods=['GET'])
@jwt_required()
def secure_download(token):
    current_user = get_jwt_identity()
    if current_user['role'] != 'client':
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        filename = serializer.loads(token, salt='file-download', max_age=3600)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        return jsonify({'message': 'File not found'}), 404
    except (BadSignature, SignatureExpired):
        return jsonify({'message': 'Invalid or expired link'}), 400

# Initialize Database
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
