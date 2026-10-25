#!/bin/bash

usageFunction()
{
  echo " "
  tput setaf 2;
  echo "Usage: $0 (-n) (-h)"
  echo -e "\t-n Non-interactive installation (Optional)"
  echo -e "\t-h Show usage"
  exit 1
}

tput setaf 2;
echo "CVEngine"

# .env is created with the database and certificate passwords already generated (it never touches a value that is set)
./scripts/init-env.sh

tput setaf 1; echo "Before running this script, please make sure Docker is running."
tput setaf 2; echo "The passwords in .env are generated for you. Set DOMAIN_NAME in it to the name people will type."

tput setaf 4;

isNonInteractive=false
while getopts nh opt; do
   case $opt in
      n) isNonInteractive=true ;;
      h) usageFunction ;;
      ?) usageFunction ;;
   esac
done

if [ $isNonInteractive = false ]; then
    read -p "Edit .env now (DOMAIN_NAME and other options)? (y/N) " answer
    case ${answer:0:1} in
        y|Y )
          nano .env
        ;;
        * )
          echo "Keeping .env as it is."
        ;;
    esac
else
  echo "Non-interactive installation parameter set. Installation begins."
fi

# Never bring up a public HTTPS instance with the example passwords from .env.example.
placeholders=$(grep -iE '^(POSTGRES_PASSWORD|AUTHORITY_PASSWORD)=.*change-me' .env | cut -d= -f1 | tr '\n' ' ')
if [ -n "$placeholders" ]; then
  tput setaf 1
  echo "Refusing to continue: .env still has the example placeholder for: $placeholders"
  echo "Run ./scripts/init-env.sh to generate them (or set your own) and run this script again."
  exit 1
fi

echo " "
tput setaf 3;
echo "#########################################################################"
echo "Please note that, this installation script is only intended for Linux"
echo "For Mac and Windows, see docs/DEPLOYMENT.md (Mac and Windows) in this repository"
echo "#########################################################################"

echo " "
tput setaf 4;
echo "Installing CVEngine and its dependencies"

echo " "
if [ "$EUID" -ne 0 ]
  then
  tput setaf 1; echo "Error installing CVEngine, Please run this script as root!"
  tput setaf 1; echo "Example: sudo ./install.sh"
  exit
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing curl..."
echo "#########################################################################"
if [ -x "$(command -v curl)" ]; then
  tput setaf 2; echo "CURL already installed, skipping."
else
  sudo apt update && sudo apt install curl -y
  tput setaf 2; echo "CURL installed!!!"
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing Docker..."
echo "#########################################################################"
if [ -x "$(command -v docker)" ]; then
  tput setaf 2; echo "Docker already installed, skipping."
else
  curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
  tput setaf 2; echo "Docker installed!!!"
fi


echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing Docker Compose"
echo "#########################################################################"
if [ -x "$(command -v docker compose)" ]; then
  tput setaf 2; echo "Docker Compose already installed, skipping."
else
  curl -L "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
  tput setaf 2; echo "Docker Compose installed!!!"
fi


echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing make"
echo "#########################################################################"
if [ -x "$(command -v make)" ]; then
  tput setaf 2; echo "make already installed, skipping."
else
  apt install make
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Checking Docker status"
echo "#########################################################################"
if docker info >/dev/null 2>&1; then
  tput setaf 4;
  echo "Docker is running."
else
  tput setaf 1;
  echo "Docker is not running. Please run docker and try again."
  echo "You can run docker service using sudo systemctl start docker"
  exit 1
fi



echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing CVEngine"
echo "#########################################################################"
make certs && make build && make up && tput setaf 2 && echo "CVEngine is installed!!!" && failed=0 || failed=1

if [ "${failed}" -eq 0 ]; then
  sleep 3

  echo " "
  tput setaf 4;
  echo "#########################################################################"
  echo "Creating your admin account"
  echo "#########################################################################"
  # the web service can still be starting: try for up to five minutes
  created=1
  for attempt in $(seq 1 30); do
    if make migrate && make admin; then created=0; break; fi
    echo "Waiting for the web service to finish starting (attempt $attempt of 30)..."
    sleep 10
  done
  if [ "$created" -ne 0 ]; then
    tput setaf 1 && echo "Could not create the admin account yet. Once the web service is up, run: make admin"
  fi

  tput setaf 2 && printf "\n%s\n" "CVEngine is installed. Open the address above, sign in with that username and password, and the setup wizard takes it from there."
  echo "Wrote your password down? It is not saved anywhere readable. Lost it: run 'make admin-password'."
  echo "If you saw unapplied migrations above in red, run 'make migrate'."
else
  tput setaf 1 && printf "\n%s\n" "CVEngine installation failed!!"
fi
