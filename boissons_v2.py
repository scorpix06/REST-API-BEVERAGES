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


accounts = []

app = Flask(__name__)
app.config['SECRET_KEY'] = 'masuperclesupersecrete'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401
  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message' : 'Invalid token'}), 401
        
        user = None
        for account in accounts:
            if account.get("id") == data['public_id']:
                user = account
                user_founded = True

                current_user = user.get("name")

        if user == None:
            return jsonify({'message' : 'Invalid token'}), 401
        else:
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
    if not auth or not auth.get('name') or not auth.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm ="Login required !!"'})

    user_founded = False

    for account in accounts:
        if account.get("name") == auth.get('name'):
            user = account
            user_founded = True
    
    if user_founded == False:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'})


    if check_password_hash(user.get("hashed_password"), auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': user.get("id"),
            'exp' : datetime.utcnow() + timedelta(minutes = 30),
            'algorithms': ["HS256"]
        }, app.config['SECRET_KEY'])
        print(token)
        print(type(token))
        return make_response(jsonify({'token' : token}), 201)

    return make_response('Could not verify', 403, {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'})

@app.route('/signup', methods =['POST'])
def signup():

    name = request.form.get('name')
    password = request.form.get('password')
    hashed_password = generate_password_hash(password)
    id = str(uuid.uuid4())

    user = {
        "name": name,
        "hashed_password": hashed_password,
        "id": id
    }
    print(user)
    accounts.append(user)
  
    return make_response('Successfully registered.', 201)

  

# Récupérer toute ou partie des boissons
@app.route('/beverages', methods=['GET'])
@token_required
def get_beverages(current_user):

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
