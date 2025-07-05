#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p certs

# Create a configuration file for the certificate with SAN
cat > certs/cert.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = backend-https
DNS.3 = frontend-https
DNS.4 = backend
DNS.5 = frontend
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# Generate self-signed certificate for development with SAN
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -config certs/cert.conf -extensions v3_req

# Set appropriate permissions
chmod 600 certs/key.pem
chmod 644 certs/cert.pem

# Clean up config file
rm certs/cert.conf

echo "SSL certificates generated successfully:"
echo "- Certificate: certs/cert.pem"
echo "- Private key: certs/key.pem"
echo ""
echo "Certificate includes the following domains:"
echo "  - localhost"
echo "  - backend-https"
echo "  - frontend-https"
echo "  - backend"
echo "  - frontend"
echo ""
echo "Note: These are self-signed certificates for development use only."
echo "Your browser will show a security warning which you can safely ignore in development." 