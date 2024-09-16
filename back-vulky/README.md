# command to run back

`pm2 start server.js -n vulky`

# command to stop back

`pm2 stop vulky`
  

# generate ssl certificates

## Windows
1. Install OpenSSL (https://slproweb.com/products/Win32OpenSSL.html)
	a.  check if OpenSSL is installed: `openssl version`
2. Create folder **ssl**: `mkdir ssl` and enter it.
3. Generate a private key: `openssl genrsa -out private.key 2048`
4. Generate CSR file: `openssl req -new -key private.key -out request.csr`
5. Generate certificate: `openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt`

## Linux
1. Install OpenSSL, either apt-get, yum or dnf.
	a.  check if OpenSSL is installed: `openssl version`
2. Create folder **ssl**: `mkdir ssl` and enter it.
3. Generate a private key: `openssl genrsa -out private.key 2048`
4. Generate CSR file: `openssl req -new -key private.key -out request.csr`
5. Generate certificate: `openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt`