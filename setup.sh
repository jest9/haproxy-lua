#!/bin/bash

sudo apt-get install lua5.4
sudo apt-get install haproxy

wget https://luarocks.org/releases/luarocks-3.11.1.tar.gz
tar zxpf luarocks-3.11.1.tar.gz
cd luarocks-3.11.1
./configure && make && sudo make install
sudo luarocks install luasocket
sudo luarocks install openssl
