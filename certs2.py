from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

with open("ca_cert.pem", "rb") as f:
    certificate_pem = f.read()

# calculate sha fingeprint on whole certificate

certificate = x509.load_pem_x509_certificate(certificate_pem)

# Create SHA1 hash object instead of SHA256
sha1_hash = hashes.Hash(hashes.SHA1())

# Use the entire certificate bytes instead of just tbs_certificate_bytes
sha1_hash.update(certificate.public_bytes(serialization.Encoding.DER))

# Calculate the hash
sha1_digest = sha1_hash.finalize()

# Convert to hex
sha1_hex = sha1_digest.hex()
print(f"Certificate SHA1 Fingerprint: {sha1_hex}")