from flask import Flask
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_jwt_extended import (
    JWTManager
)

from pyfcm import FCMNotification
app = Flask(__name__)
app.config['SECRET_KEY'] = 'c4de9cb3e77691c8e986fae55003fb75'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['JWT_SECRET_KEY'] = 'c4de9cb3e77691c8e986fae55003fb75'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(weeks=5125)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
push_service = FCMNotification(api_key="AAAASc0eqIc:APA91bFLDMjEpZRjnJmylZNjmNL7j1WH8b52sv5o6LzDyJ_wsfFTG9AcmUp4VS_dHLaypRv2H-HlYmV14QuDbvnOfYKRKcpnR1OejpiAbFe61ug7fV9oK6_VV5FelwdCl92IfagLnz_L")
jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
socketio = SocketIO(app)
from Shared import routes