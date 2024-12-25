from models import db, User, File
from flask import Blueprint, jsonify, request, url_for, send_file
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config

config = Config()
bcrypt = Bcrypt()

admin_user = Blueprint('admin_user', __name__)
cors = CORS(admin_user)

serializer = URLSafeTimedSerializer(config.SECRET_KEY)


@admin_user.route('/user/signup', methods=['POST'])
def user_signup():
    data = request.json
    existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()

    if existing_user:
        return {'message': 'Username or email already exists'}, 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()

    # Generate email verification link
    token = serializer.dumps(data['email'], salt='email-confirm')
    verification_link = url_for('admin_user.verify_email', token=token, _external=True)

    # Send verification email
    sender_email = config.sender_email
    sender_password = config.sender_password
    recipient_email = data['email']

    subject = "Verify Your Email Address"
    body = f"""
    Hi {data['username']},
    
    Please click the link below to verify your email address:
    {verification_link}

    If you did not sign up for this account, please ignore this email.
    """

    # Sending the email
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Connect to Gmail's SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return jsonify({'message': 'Signup successful. Check your email for verification link.'}), 201
    except Exception as e:
        return jsonify({'message': 'Error sending email', 'error': str(e)}), 500

@admin_user.route('/user/verify', methods=['GET'])
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

@admin_user.route('/user/login', methods=['POST'])
def user_login():
    data = request.json
    user = User.query.filter_by(username=data['username'], role='user').first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        if not user.is_verified:
            return jsonify({'message': 'Email not verified'}), 403
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@admin_user.route('/user/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = get_jwt_identity()
    if current_user['role'] != 'user':
        return jsonify({'message': 'Unauthorized'}), 403

    files = File.query.all()
    file_list = [{'id': file.id, 'filename': file.filename, 'uploaded_at': file.uploaded_at} for file in files]
    return jsonify({'files': file_list}), 200

@admin_user.route('/user/download/<int:file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'user':
        return jsonify({'message': 'Unauthorized'}), 403

    file = File.query.get(file_id)
    if not file:
        return jsonify({'message': 'File not found'}), 404

    token = serializer.dumps(file.filename, salt='file-download')
    download_link = url_for('admin_user.secure_download', token=token, _external=True)
    return jsonify({'download-link': download_link, 'message': 'success'}), 200

@admin_user.route('/secure-download/<token>', methods=['GET'])
@jwt_required()
def secure_download(token):
    current_user = get_jwt_identity()
    if current_user['role'] != 'user':
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        filename = serializer.loads(token, salt='file-download', max_age=3600)
        file_path = os.path.join(config.UPLOAD_FOLDER, filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        return jsonify({'message': 'File not found'}), 404
    except (BadSignature, SignatureExpired):
        return jsonify({'message': 'Invalid or expired link'}), 400