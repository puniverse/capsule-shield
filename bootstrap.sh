#!/usr/bin/env bash

add-apt-repository ppa:webupd8team/java
apt-get update
apt-get upgrade -y 
apt-get install -y lxc uidmap
#apt-get install -y openjdk-7-jre
echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections
apt-get install -y oracle-java8-installer
