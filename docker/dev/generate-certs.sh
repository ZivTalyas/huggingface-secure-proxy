#!/bin/bash

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Set appropriate permissions
chmod 600 certs/key.pem
chmod 644 certs/cert.pem

echo "SSL certificates generated successfully:"
echo "- Certificate: certs/cert.pem"
echo "- Private key: certs/key.pem"
echo ""
echo "Note: These are self-signed certificates for development use only."
echo "Your browser will show a security warning which you can safely ignore in development." 