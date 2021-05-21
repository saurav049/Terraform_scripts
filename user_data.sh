#!/bin/bash
sudo apt-get update -y
sudo apt-get install apache2 -y
gsutil cp gs://s14bucket/index.html /var/www/html/index.html
