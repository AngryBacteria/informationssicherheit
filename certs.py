from cryptography import x509
from cryptography.hazmat.primitives import hashes

with open("ca_cert.pem", "rb") as f:
    certificate_pem = f.read()

certificate = x509.load_pem_x509_certificate(certificate_pem)

# Get the part of the certificate which we want to hash
tbs_hash = certificate.tbs_certificate_bytes

# Create an object which will be used to hash the certificate
tbs_hash_value = hashes.Hash(hashes.SHA256())

# Feed the bytes of the certificate to the hash object
tbs_hash_value.update(tbs_hash)

# Calculate the hash
tbs_hash_digest = tbs_hash_value.finalize()

# Convert to hex for readable format
tbs_hash_hex = tbs_hash_digest.hex()
print(f"TBS Certificate Hash (SHA256): {tbs_hash_hex}")