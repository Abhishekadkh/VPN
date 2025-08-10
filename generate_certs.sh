#!/bin/bash

# VPN Certificate Generation Script
# This script generates the required certificates for the VPN server and client

set -e

echo "Generating VPN certificates..."

# Create certs directory
mkdir -p certs

# Generate CA private key
echo "Generating CA private key..."
openssl genrsa -out certs/ca.key 4096

# Generate CA certificate
echo "Generating CA certificate..."
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt -subj "/C=US/ST=State/L=City/O=VPN/CN=VPN-CA"

# Generate server private key
echo "Generating server private key..."
openssl genrsa -out certs/server.key 2048

# Generate server certificate signing request
echo "Generating server certificate signing request..."
openssl req -new -key certs/server.key -out certs/server.csr -subj "/C=US/ST=State/L=City/O=VPN/CN=VPN-Server"

# Sign server certificate with CA
echo "Signing server certificate..."
openssl x509 -req -days 365 -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt

# Generate client private key
echo "Generating client private key..."
openssl genrsa -out certs/client.key 2048

# Generate client certificate signing request
echo "Generating client certificate signing request..."
openssl req -new -key certs/client.key -out certs/client.csr -subj "/C=US/ST=State/L=City/O=VPN/CN=VPN-Client"

# Sign client certificate with CA
echo "Signing client certificate..."
openssl x509 -req -days 365 -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt

# Set proper permissions
chmod 600 certs/*.key
chmod 644 certs/*.crt

# Clean up temporary files
rm -f certs/*.csr certs/ca.srl

echo "Certificate generation completed!"
echo "Generated files:"
echo "  certs/ca.crt      - CA certificate"
echo "  certs/ca.key      - CA private key"
echo "  certs/server.crt  - Server certificate"
echo "  certs/server.key  - Server private key"
echo "  certs/client.crt  - Client certificate"
echo "  certs/client.key  - Client private key" 