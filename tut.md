# Fix shitty wsl behaviour
`sudo nano /etc/wsl.conf`
```
[interop]
appendWindowsPath=false
```

# Add vscode
`nano ~/.bashrc`
```
export PATH="/mnt/c/Users/.../AppData/Local/Programs/Microsoft VS Code/bin:$PATH"
```

# Install python
```
sudo apt update
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.13
sudo apt install python3-pip
python3.13 -m pip install -r requirements.txt
```

# Docker shiz
```
cp .env.example .env
sudo apt install docker-compose
sudo docker-compose up -d db
sudo docker-compose down -v
```

# Django cmds
## run
`python3.13 backend/manage.py runserver`
## migrate?
`python3.13 backend/manage.py makemigrations chat` \
`python3.13 backend/manage.py sqlmigrate chat 000x` \
`python3.13 backend/manage.py migrate`
## admin shizz
`python3.13 backend/manage.py createsuperuser`


# Github
```
git config --global user.name "Pierre V"
git config --global user.email "77776198+PierreV23@users.noreply.github.com"
```