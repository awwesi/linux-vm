# Project Linux Server Configuration

Configuring Linux Web Servers to make secure and run a python flask app

## Description

This project is setting up and configuring a Linux Webserver
* Security settings for ssh and web
* Add another user and disabling remote login for root
* Key-based SSH authentication and set up a firewall
* set up Website "Project Catalog App"
* Server IP: 3.120.186.203

## Getting Started

### Dependencies

* a simple webserver running localhost
* ssh client, if you want to connect to the server

### Summary of Installing

* Creating Amazon Lightsail Account 
* Create a virtual image with a plain ubuntu linux
* Installing Flask, sqlalchemy, postgresql, psycopg2, passlib
* Add a user grader, who can run commands using sudo
* change ssh port to 2200
* enforcing Key-based SSH authentication
* disable remote login for user root
* set up firewall with SSH (port 2200), HTTP (port 80), and NTP (port 123)
* Configuring Apache Webserver to serve the Item Catalog application as a WSGI app
* clone Catalog App from github and configure it running on that server

### Executing program

* IP of the server: 3.120.186.203
* call http://3.120.186.203 in your browser
* for ssh use the user "grader" with the SSH key 

## Authors

Alexander Wesendonk  
alexander (at) wesendonk (dot) de

## License

This project is licensed under the [MIT](https://mit-license.org/) License

## Acknowledgments

This code was programmed because of the Udacity course Full Stack Web Developer

* [Full Stack Web Developer](https://de.udacity.com/course/full-stack-web-developer-nanodegree--nd004)