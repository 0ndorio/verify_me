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

echo "Installing Python3 & pip3"
apt-get install -y python3-dev > /dev/null
apt-get install -y python3-pip > /dev/null

echo "Configure Python3: virtualenv"
pip3 install virtualenv
mkdir -p ${application_name}
virtualenv ${application_name}/virtual_env
source ${application_name}/virtual_env/bin/activate

echo "Cofigure Python3: install modules"
pip3 install tornado > /dev/null

echo "Copy Dummy Application"
mkdir -p ${application_name}/src
cp /vagrant/src/DummyApplication.py ${application_name}/src/DummyApplication.py
cp /vagrant/src/util_scripts/run_server.sh ${application_name}/run_server.sh

echo "Run application"
/bin/bash ${application_name}/run_server.sh &
