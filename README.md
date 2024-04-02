# ECDH_Feistel

## A Client-Server ECDH & Feistel Cipher (CBC & ECB modes) Application

A Client-Server model that facilitates encrypted files between a server and a minimum of two clients. The machines exchange symmetric session keys using ECDH and a Feister Cipher using CBC and ECB modes for bulk encryption to send and receive encrypted files between two networked machines.

### Install nummaster and tinyec using the commands:

```pip install nummaster```

```pip install tinyec```

### To run server.py:

```python server.py -i [ip] -p [port]```

### To run client.py:

```python client.py -i [ip] -p [port] -f [file_name] -n [client_name] -e (optional)```
