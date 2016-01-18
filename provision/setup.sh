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
locale-gen UTF-8 > /dev/null

echo "Installing Nginx"
apt-get install -y nginx > /dev/null

echo "Configuring Nginx: certificate creation"
mkdir -p /etc/nginx/ssl > /dev/null
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -subj "/C=${openssl_country}/ST=./L=./O=./CN=${openssl_cn}" \
            -keyout /etc/nginx/ssl/nginx.key \
            -out /etc/nginx/ssl/nginx.crt 2> /dev/null
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 1024 2> /dev/null

echo "Configuring Nginx: config"
cp /vagrant/provision/config/nginx_vhost /etc/nginx/sites-available/nginx_vhost > /dev/null
ln -s /etc/nginx/sites-available/nginx_vhost /etc/nginx/sites-enabled/ > /dev/null

rm -rf /etc/nginx/sites-available/default > /dev/null
rm -rf /etc/nginx/sites-enabled/default > /dev/null

echo "Configuring Nginx: restart service"
service nginx restart > /dev/null

echo "Installing Git"
apt-get install -y git > /dev/null

echo "Cloning repository"
git clone --recursive https://github.com/0ndorio/verify_me.git ${application_name} > /dev/null

echo "Installing node.js & npm"
curl -sL https://deb.nodesource.com/setup_5.x | sudo -E bash - > /dev/null
apt-get install -y build-essential nodejs > /dev/nul
npm install -g npm > /dev/null

echo "Configure & build client"
cp /vagrant/client/dist/* ${application_name}/client/dist/

echo "Link Utility"
cd ${application_name}/utility
npm install --no-optional --silent > /dev/null
npm ddp
npm run build
npm link
cd ../../

echo "Configure & run server"
cd ${application_name}/server
npm install --no-optional --silent > /dev/null
npm link verifyme_utility
npm ddp > /dev/null
cd ../../
