# Python Flask REST API with JWT authentication and SQL databases

This repository is school project on REST API. It use Python Flask to create a REST API connected to a sqlite3 database. 


### Quick setup with docker 

```bash
  docker run -p 5000:5000 scorpix06/beverages:1.0
```
    

### Install from source

```bash
  sudo apt install python3-pip git -yq
  git clone https://github.com/scorpix06/fortigate-python-apikey-generator.git
  cd ./fortigate-python-apikey-generator
  python3 -m pip install -r requirements.txt
```

### Authentication

Authentication is managed by a database containing name, password and uuid. 

The steps to authenticate is :

1) /signin endpoint allow users to create an account witch name and password
2) /login with name and password in the body (form-data) return a token wich could be used to use the API
2) The generated token is valid during 1 hour, to request the API, the token must be in the header.

### Documentation 

There is no documentation yet for this project but all the requests of the API are available in a postman collection wich can be imported with the "beverages_REST_API.postman_collection.json" file.


### Some examples of curl requests

#### Signin :

```
  curl --location 'http://127.0.0.1:5000/signup' \
  --form 'name="user"' \
  --form 'password="test"'
```
#### Login :

``` 
curl --location 'http://127.0.0.1:5000/login' \
--form 'name="user"' \
--form 'password="test"'

```

#### Create new beverages :

``` 
curl --location 'http://127.0.0.1:5000/beverages' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'token: <your_token_here>' \
--data '{
    "nom": "1664",
    "type": "biere",
    "description": "biere blonde 1664 ",
    "alcool": "5",
    "contenance": "33",
    "contenance_restante": "33",
    "pays": "france",
    "nez": "doux",
    "bouche": "douces",
    "finale": "ma foie, tu le sais toi ?"
}
'
```

#### Read all beverages:
``` 
curl --location 'http://127.0.0.1:5000/beverages' \
--header 'token: <your_token_here>'
```

#### Read with filter (available filter : nom, pays, id, alcool, contenance, contenance_restante, nez, bouche, finale): 
``` 
curl --location 'http://127.0.0.1:5000/beverages?pays=france' \
--header 'token:  <your_token_here>'
```
#### Update a beverage
``` 
curl --location --request PUT 'http://127.0.0.1:5000/beverages/<id>' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'token: <your_token_here>' \
--data '{
    "nom": "1664",
    "type": "biere",
    "description": "biere blonde 1664 ",
    "alcool": "6",
    "contenance": "25",
    "contenance_restante": "25",
    "pays": "france",
    "nez": "Doux",
    "bouche": "Douces",
    "finale": "ma foie, tu le sais toi ?"
}
'
```

#### Delete a beverage
``` 
curl --location --request DELETE 'http://127.0.0.1:5000/beverages/<id>' \
--header 'token: <your_token_here>'
```

More requests available in the postman file :)