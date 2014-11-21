#!/usr/bin/env bash

add-apt-repository ppa:webupd8team/java
apt-get update
apt-get upgrade -y 
apt-get install -y lxc uidmap
apt-get install -y openjdk-7-jre
apt-get install oracle-java8-installer
