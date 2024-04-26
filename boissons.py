#!/usr/bin/env python

from flask import Flask, request, jsonify, make_response
import sqlite3
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps



# Initialisation de la base de donnée si elle n'existe pas encore
db_name = "beverages"
db_file = "beverages.db"
conn = sqlite3.connect(db_file, check_same_thread=False)
cursor = conn.cursor()
cursor.execute(f"""
CREATE TABLE IF NOT EXISTS {db_name} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    type TEXT NOT NULL,
    description INTEGER NOT NULL,
    alcool REAL NOT NULL,f
    contenance REAL NOT NULL,
    contenance_restante REAL NOT NULL,
    pays TEXT NOT NULL,
    nez TEXT NOT NULL,
    bouche TEXT NOT NULL,
    finale TEXT NOT NULL
)
""")               
conn.commit()

# On creer la base de donnée des utilisateurs
conn = sqlite3.connect("accounts.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute(f"""
CREATE TABLE IF NOT EXISTS user (
    user.id INTEGER PRIMARY KEY AUTOINCREMENT,
    user.name TEXT NOT NULL,
    user.password TEXT NOT NULL
)
""")      


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'MA-CLE-SUPER-SECRETE-EST-TRES-SECRETE-ELLE-NE-SE-RETROUVE-PAS-SUR-GITHUB'
db = SQLAlchemy(app)


# Classe permettant d'envoyer des utilisateurs dans une db 
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(80))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401
  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401
        return  f(current_user, *args, **kwargs)
  
    return decorated

@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email
        })
  
    return jsonify({'users': output})
  
@app.route('/login', methods =['POST'])
def login():
    auth = request.form
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm ="Login required !!"'})

    user = User.query.filter_by(email = auth.get('email')).first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)

    return make_response('Could not verify', 403, {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'})

@app.route('/signup', methods =['POST'])
def signup():

    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(name = name).first()
    if not user:
        # database ORM object
        user = User(
            name = name,
            password = generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)
  

# Récupérer toute ou partie des boissons
@app.route('/beverages', methods=['GET'])
def get_beverages():

    # Si pas de parametre dans l'url, renvoi la totalité des boissons
    if len(request.args) == 0:
        request.args.get('username')
        cursor.execute(f"SELECT * FROM {db_name}")
        beverages = cursor.fetchall()

        return jsonify(beverages)
    
    # L'API ne gere qu'un seul argument de recherche a la fois, pour le moment :) 
    elif len(request.args) == 1:
        arg = list(request.args.keys())[0]
        arg_value = request.args.get(list(request.args.keys())[0])
        argument_valable = ["nom", "type", "description", "alcool", "contenance", "contenance_restante", "pays", "nez", "bouche", "finale", "id"]
        
        # On verifie que l'argument rentré fait parti des colonnes de notre base de données
        if arg in argument_valable:
            cursor.execute(f"SELECT * FROM {db_name} WHERE {arg}='{arg_value}'")
            beverages = cursor.fetchall()

            if not beverages or beverages is None:
                return jsonify({'message': 'Beverage not found'}), 404
            return jsonify(beverages)

        else:
            return jsonify({'message': 'Argument not recognize'}), 404

    else:
        return jsonify({'message': 'Too many arguments'}), 404


# Ajouter une nouvelle boissons

@app.route('/beverages', methods=['POST'])
def add_beverage():
    cursor.execute(f"""
    INSERT INTO {db_name} (nom, type, description, alcool, contenance, contenance_restante, pays, nez, bouche, finale) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
    """, (request.json['nom'], 
          request.json['type'],
          request.json['description'],
          request.json['alcool'], 
          request.json['contenance'],
          request.json['contenance_restante'],         
          request.json['pays'],
          request.json['nez'],
          request.json['bouche'],
          request.json['finale'],           
          ))
    conn.commit()

    return jsonify({'message': 'Beverage added with success'}), 201




# Mettre a jour une boisson existante
@app.route('/beverages/<int:id>', methods=['PUT'])
def update_beverage(id):
    cursor.execute(f"""
    UPDATE {db_name} SET nom=?, type=?, description=?, alcool=?, contenance=?, contenance_restante=?, pays=?, nez=?, bouche=?, finale=? WHERE id=?
    """, (request.json['nom'], 
          request.json['type'],
          request.json['description'],
          request.json['alcool'], 
          request.json['contenance'],
          request.json['contenance_restante'],         
          request.json['pays'],
          request.json['nez'],
          request.json['bouche'],
          request.json['finale'], 
          id          
          ))
    conn.commit()

    return jsonify({'message': 'Beverage updated with success'}), 201

# Supprimer une boisson 
@app.route('/beverages/<int:id>', methods=['DELETE'])
def delete_beverage(id):
    cursor.execute(f"DELETE FROM {db_name} WHERE id={id}")
    conn.commit()

    return jsonify({'message': 'Beverage deleted with success'}), 201

# Supprimer toutes les boissons (effacer la base de donnée)
@app.route('/beverages/all', methods=['DELETE'])
def supprimer_chaussures():
    cursor.execute(f"DELETE FROM {db_name}")
    conn.commit()

    return jsonify({'message': 'All beverage deleted with success'}), 201


if __name__ == '__main__':
    app.run(debug=True)
