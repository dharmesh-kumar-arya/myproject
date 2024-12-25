from models import db, User, File
from flask import Blueprint, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

from config import Config

config = Config()
bcrypt = Bcrypt()


admin_ops = Blueprint('admin_ops', __name__)
cors = CORS(admin_ops)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

@admin_ops.route('/admin/login', methods=['POST'])
def ops_login():
    data = request.json
    user = User.query.filter_by(username=data['username'], role='ops').first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@admin_ops.route('/admin/upload', methods=['POST'])
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
        if not os.path.exists(config.UPLOAD_FOLDER):
            os.makedirs(config.UPLOAD_FOLDER)
        file.save(os.path.join(config.UPLOAD_FOLDER, filename))
        new_file = File(filename=filename, uploaded_by=current_user['id'])
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully'}), 201
    else:
        return jsonify({'message': 'File type not allowed'}), 400
