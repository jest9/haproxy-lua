# haproxy-lua

quick and easy cookie encryption at haproxy reverse proxy via lua.

used this cool library here : https://github.com/zhaozg/lua-openssl

 # setup
 uses openssl library from luarocks
 install luarocks following the steps from https://luarocks.org/
 
 ```
 sudo luarocks install openssl
 ```

 make sure it is installed to the correct directory, the same dir for the version of lua your haproxy installation is using.

 # future improvements

 may write my own lua wrapper for openssl so I don't have to use library
