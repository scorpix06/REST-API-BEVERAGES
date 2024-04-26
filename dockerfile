FROM python:3.8-slim

# Copie du script Python dans le conteneur
COPY . /app
WORKDIR /app

# Installation des dépendances Python définies dans requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Exposition du port 5000 pour accéder à l'application Flask
EXPOSE 5000

# Commande à exécuter lorsque le conteneur démarre
CMD ["python", "beverages.py"]
