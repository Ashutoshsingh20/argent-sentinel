Place TLS cert material here for HTTPS listener on port 8443.

Expected files:
- server.crt
- server.key

For local development only, generate a self-signed cert:

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt -subj "/CN=localhost"
