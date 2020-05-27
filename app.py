from flask import Flask, jsonify, make_response, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy 
from passlib.hash import pbkdf2_sha256 as sha256
import os
app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Init db
db = SQLAlchemy(app)
# JWT Secret key config
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
# init jwt
jwt = JWTManager(app)

def get_hash(password):
        return sha256.hash(password)
    
def verify_hash(password, hash):
        return sha256.verify(password, hash)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    email = db.Column(db.String(), unique=True)
    password = db.Column(db.String())
  
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = get_hash(password)
    
    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email = email).first()


@app.route('/login')
def login():
    data = request.json
    user = User.find_by_email(email=data['email'])
    if user:
        if verify_hash(data['password'], user.password):
            access_token = create_access_token(identity=user.email)
            return jsonify(access_token=access_token), 200
    return 'email or password are wrong', 401

@app.route('/signup')
def signup():
    data = request.json
    user=User(name=data['name'],email=data['email'],password=data['password'])
    db.session.add(user)
    db.session.commit()
    return 'signed'

@app.route('/content')
@jwt_required
def content():
    return 'content'

@app.route('/user')
@jwt_required
def user():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run(debug=True)