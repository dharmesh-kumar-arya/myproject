import os
import datetime
import json
try:
    config = json.loads(open("config.json").read())
except:
    config = json.loads(open("democonfig.json").read())

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', config['SECRET_KEY'])  # Secret key for session management and JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', config['JWT_SECRET_KEY'])  # Secret key for JWT
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(hours=os.getenv('JWT_SECRET_KEY', config['JWT_ACCESS_TOKEN_EXPIRES']))  # Expiry time in hours for JWT
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=os.getenv('JWT_SECRET_KEY', config['JWT_REFRESH_TOKEN_EXPIRES']))  # Expiry time in hours for JWT
    UPLOAD_FOLDER  = os.getenv('UPLOAD_FOLDER', config['UPLOAD_FOLDER']) # './uploads'
    ALLOWED_EXTENSIONS  = os.getenv('ALLOWED_EXTENSIONS', config['ALLOWED_EXTENSIONS']) # './uploads'
    sender_email  = os.getenv('sender_email', config['sender_email']) 
    sender_password  = os.getenv('sender_password', config['sender_password']) 

    SQLALCHEMY_DATABASE_URI = 'sqlite:///file_sharing.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = config['SQLALCHEMY_TRACK_MODIFICATIONS']

    DEBUG = config['DEBUG']
    PORT = config['PORT']
