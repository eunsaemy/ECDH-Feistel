# ECDH_Feistel

## A Client-Server ECDH & Feistel Cipher (CBC & ECB modes) Application

A Client-Server model that facilitates encrypted files between a server and a minimum of two clients. The machines exchange symmetric session keys using ECDH and a Feister Cipher using CBC and ECB modes for bulk encryption to send and receive encrypted files between two networked machines.

### Install nummaster and tinyec using the commands:

```pip install nummaster```

```pip install tinyec```

### To run server.py:

```python server.py -i [server_ip] -p [port]```

#### Example:

```python server.py -i 192.168.0.10 -p 8000```

### To run client.py:

```python client.py -i [server_ip] -p [port] -f [file_name] -n [client_name] -e (optional)```

#### Example (CBC Mode):

```python client.py -i 192.168.0.10 -p 8000 -f animal.bmp -n 192.168.0.11```

#### Example (ECB Mode):

```python client.py -i 192.168.0.10 -p 8000 -f animal.bmp -n 192.168.0.11 -e```

### Results:

#### animal.bmp:

![image](https://github.com/eunsaemy/ECDH_Feistel/assets/45950166/daff9a7c-fb54-44e7-bc8c-5dc47ba106ea)

### animal.bmp (CBC Mode):

![image](https://github.com/eunsaemy/ECDH_Feistel/assets/45950166/f8617860-8b65-449f-80dc-3f12f679f92d)

### animal.bmp (ECB Mode):

![image](https://github.com/eunsaemy/ECDH_Feistel/assets/45950166/f2d3c148-0ba2-4afd-a984-901523b4de67)
