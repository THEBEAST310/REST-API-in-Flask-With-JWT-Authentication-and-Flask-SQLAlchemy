from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import jwt
import query

import uuid
from werkzeug.security import generate_password_hash, check_password_hash

import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\user\\Desktop\\PYTHON_NEW\\book_details.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amazon_url = db.Column(db.String(2000))
    author = db.Column(db.String(2000))
    genre = db.Column(db.String(2000))
    title = db.Column(db.String(2000))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<id>', methods=['GET'])
@token_required
def get_one_user(current_user, id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<id>', methods=['PUT'])
@token_required
def promote_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/book', methods=['GET'])
@token_required
def get_all_books(current_user):


    books = Books.query.all()
    output = []

    for book in books:
        book_data = {}
        
        book_data['id'] = book.id
        book_data['author'] = book.author
        book_data['genre'] = book.genre
        book_data['title'] = book.title
        book_data['amazon_url'] = book.amazon_url
        output.append(book_data)

    return jsonify({'Books' : output})

@app.route('/book/<book_id>', methods=['GET'])
@token_required
def get_one_book(current_user, book_id):
    book = Books.query.filter_by(id=book_id).first()

    if not book:
        return jsonify({'message' : 'No book found!'})

    book_data = {}
    book_data['id'] = book.id
    book_data['title'] = book.title
    book_data['amazon_url'] = book.amazon_url
    book_data['genre'] = book.genre
    book_data['author'] = book.author

    return jsonify(book_data)

@app.route('/book', methods=['POST'])
@token_required
def create_books(current_user):
    data = request.get_json()

    new_book = Books(amazon_url=data['amazon_url'],author=data['author'],genre=data['genre'],title=data['title'])
    db.session.add(new_book)
    db.session.commit()

    return jsonify({'message' : "Book created!"})

@app.route('/book', methods=['PUT'])
@token_required
def update_book(current_user):
   
    data = request.get_json()
    book = Books.query.filter_by(id=data['id']).first()
    if not book:
        return jsonify({'message' : 'No book found!'})

    book.amazon_url=data['amazon_url']
    book.id=data['id']
    book.title=data['title']
    book.genre=data['genre']
    db.session.commit()

    return jsonify({'message' : 'Book item has been updated!'})

@app.route('/book/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id):
    book = Books.query.filter_by(id=book_id).first()

    if not book:
        return jsonify({'message' : 'No Book found!'})

    db.session.delete(book)
    db.session.commit()

    return jsonify({'message' : 'Book item deleted!'})

if __name__ == '__main__':
    app.run(debug=True)