dropbear-like client-server chat with ssh-like 16 bit integer algos

previous versions, just proof of concept

```
securetelnet
self-test OK: G=11
usage:
  ./securetelnet2 [-d] test
  ./securetelnet2 [-d] keygen <privfile> <pubfile>
  ./securetelnet2 [-d] server <port> <authorized_keys>
  ./securetelnet2 [-d] client <host> <port> <privfile>
  -d, --debug  enable debug output

