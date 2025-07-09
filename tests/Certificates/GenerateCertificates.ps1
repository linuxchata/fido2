# Generate CA Root Certificate
openssl genrsa -des3 -out example-ca.key 2048
openssl req -x509 -new -nodes -key example-ca.key -subj "/CN=example-ca" -sha256 -days 1825 -out example-ca.pem
openssl x509 -outform der -in example-ca.pem -out example-ca.crt

# Generate Private Key for example.com
openssl genrsa -out example.com.key 2048

# Generate CSR
openssl req -new -key example.com.key -subj "/CN=example.com" -out example.com.csr

# Sign Certificate with CA and include SANs (example.com, login.example.com, m.login.example.com)
openssl x509 -req -in example.com.csr -CA example-ca.pem -CAkey example-ca.key -CAcreateserial -out example.com.crt -days 1825 -sha256 -extfile example.com.ext

# Convert certificate to PEM
openssl x509 -in example.com.crt -out example.com.pem -outform PEM

# Export to PFX
openssl pkcs12 -export -in example.com.crt -inkey example.com.key -out example.com.pfx