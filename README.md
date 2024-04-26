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