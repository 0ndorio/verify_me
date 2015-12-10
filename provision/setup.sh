#!/bin/bash

# Some Config
application_name="my_app"
openssl_country="DE"
openssl_cn="192.168.33.10"

# Provision
echo "Provisioning virtual machine ..."

echo "Updating repositories"
apt-get update > /dev/null
apt-get upgrade -y > /dev/null
locale-gen UTF-8

echo "Installing Nginx"
apt-get install -y nginx > /dev/null

echo "Configuring Nginx: certificate creation"
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -subj "/C=${openssl_country}/ST=./L=./O=./CN=${openssl_cn}" \
            -keyout /etc/nginx/ssl/nginx.key \
            -out /etc/nginx/ssl/nginx.crt 2> /dev/null
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 1024 2> /dev/null

echo "Configuring Nginx: config"
cp /vagrant/provision/config/nginx_vhost /etc/nginx/sites-available/nginx_vhost > /dev/null
ln -s /etc/nginx/sites-available/nginx_vhost /etc/nginx/sites-enabled/

rm -rf /etc/nginx/sites-available/default
rm -rf /etc/nginx/sites-enabled/default

echo "Configuring Nginx: restart service"
service nginx restart > /dev/null

echo "Installing Git"
apt-get install -y git

echo "Cloning repository"
git clone --recursive https://github.com/0ndorio/verify_me.git ${application_name}

echo "Installing Python & pip"
apt-get install -y python-dev > /dev/null
apt-get install -y python-pip > /dev/null

echo "Configure Python: virtualenv"
pip install virtualenv
virtualenv ${application_name}/virtual_env
source ${application_name}/virtual_env/bin/activate

echo "Cofigure Python: install modules"
pip install tornado > /dev/null
pip install PyCrypto > /dev/null

echo "Copy Dummy Keys"
mkdir -p ${application_name}/keys
cp /vagrant/provision/config/dummy_server.key ${application_name}/keys/server.key
cp /vagrant/provision/config/dummy_server_secret.key ${application_name}/keys/server_secret.key

#echo "Run application"
#/bin/bash ${application_name}/src/util_scripts/run_server.sh &
