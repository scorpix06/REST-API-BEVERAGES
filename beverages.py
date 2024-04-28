#!/usr/bin/env python

from flask import Flask, request, jsonify, make_response, render_template
import flask
import sqlite3
import uuid 
from  werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import platform


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
    alcool REAL NOT NULL,
    contenance REAL NOT NULL,
    contenance_restante REAL NOT NULL,
    pays TEXT NOT NULL,
    nez TEXT NOT NULL,
    bouche TEXT NOT NULL,
    finale TEXT NOT NULL
)
""")               
conn.commit()

# Initialisation de la base de donnée des utilisateurs
accounts_db_name = "accounts"
accounts_db_file = "accounts.db"
accounts_conn = sqlite3.connect(accounts_db_file, check_same_thread=False)
accounts_cursor = accounts_conn.cursor()

accounts_cursor.execute(f"""
CREATE TABLE IF NOT EXISTS {accounts_db_name} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL,
    name TEXT NOT NULL,
    hashed_password TEXT NOT NULL
)
""")               
accounts_conn.commit()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'masuperclesupersecreteestsurgithub,pasbien'


@app.route('/')
@app.route('/infos')
def infos():
    py_version = str(platform.python_version())
    flask_version = str(flask.__version__)
    api_version = "1.3"

    if request.content_type == "application/json":
        return jsonify({
                'python_version' : py_version,
                'flask_version' : flask_version,
                'api_version': api_version
                })
        
    return render_template('infos.html', py_version=py_version, flask_version=flask_version, api_version=api_version)
  

# Fonction qui verifie si un token est valide ou non, sera appelé en decorateur pour chaque endpoint de notre API 
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # Verifie que la requete contient un token dans le header
        token = None
        if 'token' in request.headers:
            token = request.headers['token']
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401
  
        # Tente de decoder le token
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message' : 'Invalid token (impossible to decode token)'}), 401

        # Grace a l'uuid (obtenu en decodant le token), verifie que l'uuid appartient bien a un user de notre API
        accounts_cursor.execute(f"SELECT * FROM {accounts_db_name} WHERE public_id='{data['public_id']}'")
        matching_user = accounts_cursor.fetchall()

        if len(matching_user) == 0:
            return jsonify({'message' : 'Invalid token'}), 401
            
        user = matching_user[0] # Au format tuple (id, id_public, name, hashed_password)
        return  f(user[2], *args, **kwargs)

    return decorated

  
@app.route('/login', methods =['POST'])
def login():
    
    # Verification que le name et le password ont été fournis dans la requete
    auth = request.form
    if not auth or not auth.get('name') or not auth.get('password'):
        return jsonify({'message': 'Credentials are required (name, password)'}), 401

    # Recuperation du compte avec le name renseigné dans la base de donnée
    name = auth.get('name')
    accounts_cursor.execute(f"SELECT * FROM {accounts_db_name} WHERE name='{name}'")
    matching_user = accounts_cursor.fetchall()

    # Si pas d'utilisateur trouvé dans la base de donnée
    if len(matching_user) == 0:
        return jsonify({'message': 'User does not exist'}), 401

    user = matching_user[0] # Au format tuple (id, id_public, name, hashed_password)

    # Comparaison des hash de mot de passe
    if check_password_hash(user[3], auth.get('password')):
        # Genere le token JWT
        token = jwt.encode({
            'public_id': user[1],
            'exp' : datetime.utcnow() + timedelta(minutes = 30),
            'algorithms': ["HS256"]
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token}), 201

    return jsonify({'message': 'Wrong Password'}), 403


@app.route('/signup', methods =['POST'])
def signup():

    name = request.form.get('name')
    password = request.form.get('password')

    accounts_cursor.execute(f"SELECT * FROM {accounts_db_name} WHERE name='{name}'")
    matching_user = accounts_cursor.fetchall()

    if len(matching_user) >= 1:
        return jsonify({'message' : 'User already exist'}), 409
    
    hashed_password = generate_password_hash(password)
    id = str(uuid.uuid4())

    user = {
        "name": name,
        "hashed_password": hashed_password,
        "public_id": id
    }

    # Creation de l'utilisateur dans la base de donnée
    accounts_cursor.execute(f"""
    INSERT INTO {accounts_db_name} (public_id, hashed_password, name) VALUES (?, ?, ?) 
    """, (user['public_id'], 
          user['hashed_password'],
          user['name'],    
          ))
    accounts_conn.commit()

    return jsonify({'message' : 'Successfully registered.'}), 201

@app.route('/users', methods =['DELETE'])
@auth_required
def del_user(username):
    
    # Verification que le name et le password ont été fournis dans la requete
    auth = request.form
    if not auth or not auth.get('name') or not auth.get('password'):
        return jsonify({'message' : 'Login required'}), 401

    # Recuperation du compte avec le name renseigné dans la base de donnée
    name = auth.get('name')
    accounts_cursor.execute(f"SELECT * FROM {accounts_db_name} WHERE name='{name}'")
    matching_user = accounts_cursor.fetchall()

    # Si pas d'utilisateur trouvé dans la base de donnée
    if len(matching_user) == 0:
        return jsonify({'message' : 'User does not exist'}), 401   

    user = matching_user[0] # Au format tuple (id, id_public, name, hashed_password)

    # Comparaison des hash de mot de passe
    if check_password_hash(user[3], auth.get('password')):
        # Supression du compte 
        accounts_cursor.execute(f"DELETE FROM {accounts_db_name} WHERE name='{user[2]}'")
        accounts_conn.commit()
        return jsonify({'message': 'Account deleted'}), 201

    return jsonify({'message': 'Wrong password'}), 403

@app.route('/users', methods =['get'])
@auth_required
def get_users(username):
        accounts_cursor.execute(f"SELECT * FROM {accounts_db_name}")
        users = accounts_cursor.fetchall()

        return jsonify(users)

# Récupérer toute ou partie des boissons
@app.route('/beverages', methods=['GET'])
@auth_required
def get_beverages(username):
    
    # Si pas de parametre dans l'url, renvoi la totalité des boissons
    if len(request.args) == 0:
        cursor.execute(f"SELECT * FROM {db_name}")
        beverages = cursor.fetchall()

        return jsonify(beverages)
    
    # L'API ne gere qu'un seul argument de recherche a la fois, pour le moment :) 
    elif len(request.args) == 1:
        arg = list(request.args.keys())[0]
        arg_value = request.args.get(list(request.args.keys())[0])
        argument_valable = ["nom", "type", "description", "alcool", "contenance", "contenance_restante", "pays", "nez", "bouche", "finale", "id"]
        
        # Verifie que l'argument rentré fait parti des colonnes de notre base de données
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
@auth_required
def add_beverage(username):
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
@auth_required
def update_beverage(username, id):
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
@auth_required
def delete_beverage(username, id):

    # Verifie que qu'il y'a bien une entree pour la boissons voulant etre supprimé
    cursor.execute(f"SELECT * FROM {db_name} WHERE id='{id}'")
    beverages = cursor.fetchall()
    if not beverages or beverages is None:
        return jsonify({'message': 'Beverage not found'}), 404

    cursor.execute(f"DELETE FROM {db_name} WHERE id={id}")
    conn.commit()
    return jsonify({'message': 'Beverage deleted with success'}), 202

# Supprimer toutes les boissons (effacer la base de donnée)
@app.route('/beverages/all', methods=['DELETE'])
@auth_required
def del_all_beverages(username):
    cursor.execute(f"DELETE FROM {db_name}")
    conn.commit()

    return jsonify({'message': 'All beverage deleted with success'}), 201


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
