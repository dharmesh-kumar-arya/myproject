from flask import Flask 
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from config import Config
from models import db
from flask_bcrypt import Bcrypt

bcrypt_flask = Bcrypt()


app = Flask(__name__, static_url_path='/static')
app.config.from_object('config.Config')

jwt = JWTManager()

jwt.init_app(app)

from main.admin_ops import admin_ops
from main.admin_client import admin_user

app.register_blueprint(admin_ops)
app.register_blueprint(admin_user)

db.init_app(app)
migrate = Migrate(app, db)

if (__name__ == "__main__"):
    with app.app_context():
        db.create_all()

    app.run(port=Config.PORT, debug=True) 