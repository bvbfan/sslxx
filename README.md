sslxx
=====
C++11 header only secure sockets

Test compilation on Linux:
--------------------------
  * you need openssl (abi+api packages)
  * openssl req -x509 -newkey rsa:4096 -keyout server.pem -out server.pem -days 365 -nodes
  * g++ -Wall --std=c++11 -O3 -s test.cpp -o test -lssl -lcrypto -lpthread
  * -lpthread may needed due to gcc bug

Contributions are welcome
-------------------------
