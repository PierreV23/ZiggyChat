# Installeer docker & database
```
sudo apt update
cp .env.example .env
sudo apt install docker-compose
sudo docker-compose up -d db
sudo docker-compose down -v
```

# Initialiseer database
`python backend/manage.py makemigrations`
`python backend/manage.py migrate`

# Run server
`python backend/manage.py runserver`

De server zal automatisch beschikbaar zijn op `http://localhost:8000/` vanwege django.