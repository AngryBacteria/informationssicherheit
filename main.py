import hashlib
import hmac
import math
import random
import time
from math import log2, ceil
from typing import Union, Literal
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import requests

NumberSystem = Literal["hex", "dec", "bin", "oct"]


def convert_number(
        number: Union[str, int],
        from_system: Literal["hex", "dec", "bin", "oct"],
        to_system: NumberSystem,
) -> str:
    if isinstance(number, str):
        number = number.replace(" ", "")
        number = number.replace("_", "")

    # Convert input to integer
    if from_system == "dec":
        int_value = int(number)
    elif from_system == "hex":
        int_value = int(number, 16)
    elif from_system == "bin":
        int_value = int(number, 2)
    elif from_system == "oct":
        int_value = int(number, 8)
    else:
        raise ValueError("Invalid 'from' number system")

    # Convert integer to desired output format
    if to_system == "dec":
        return str(int_value)
    elif to_system == "hex":
        return hex(int_value)[2:]  # Remove '0x' prefix
    elif to_system == "bin":
        return bin(int_value)[2:]  # Remove '0b' prefix
    elif to_system == "oct":
        return oct(int_value)[2:]  # Remove '0o' prefix
    else:
        raise ValueError("Invalid 'to' number system")


def every_nth_character(text: str, n: int) -> str:
    """
    Returns every nth character of a string, including the first character
    """
    return text[0::n]


# Calculate the number of possibilities for a password of a given length and number of unique characters
def password_possibilities(length: int, unique_characters: int) -> int:
    return unique_characters ** length


# Calculate the entropy of a password with a given length and number of unique characters
def password_entropy(length: int, unique_characters: int, ceil_value=True) -> float:
    value = length * log2(unique_characters)
    if ceil_value:
        return ceil(value)
    return value


def check_ean13_checksum(code: str) -> bool:
    """
    Check if an EAN-13 code has a valid checksum (the checksum at the end needs to be included in the input)
    """
    checksum = 10 - sum(
        (int(code[i]) if i % 2 == 0 else int(code[i]) * 3) for i in range(12)
    ) % 10

    # Check if the checksum is correct
    return checksum == int(code[12])


# Checks if a number is valid by the luhn algorithm
def is_valid_luhn(number: str | int) -> bool:
    # Remove any spaces or hyphens
    number = str(number)
    number = number.replace(" ", "").replace("-", "")

    # Check if the number contains only digits
    if not number.isdigit():
        return False

    # Convert to integers and reverse the digits
    digits = [int(d) for d in number][::-1]

    # Double every second digit and subtract 9 if > 9
    for i in range(1, len(digits), 2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9

    # Sum all the digits
    total = sum(digits)

    # The number is valid if the sum is divisible by 10
    return total % 10 == 0


def generate_luhn_checkdigit(partial_number: str | int) -> str:
    """
    Generate the check digit for a partial number (without the check digit)
    """
    partial_number = str(partial_number)
    for check_digit in range(10):
        if is_valid_luhn(partial_number + str(check_digit)):
            return partial_number + str(check_digit)


# Generates numbers by using a linear congruential generator
def linear_congruential_generator(init_x: int, a=6, b=0, m=13, n=1):
    output = []
    x = init_x
    for _ in range(n):
        output.append(x)
        x = (a * x + b) % m
    return output


def decrypt_xor(ciphertext: bytes, key: int):
    return "".join(chr(c ^ key) for c in ciphertext)


# Brute force a cipher text by trying all different keys in a range from 0 to 256
# Uses a hex string as input
def brute_force_xor_cypher(
        cypher_text="f7 d0 d8 d1 cc d3 df ca d7 d1 d0 cd cd d7 dd d6 db cc d6 db d7 ca 9e fc ea e6 86 8e 88 8b 9e "
                    "8c 8c 91 8c 8d",
        filter_non_ascii=True,
):
    # Hexadezimal-String in Bytes umwandeln
    ciphertext = bytes.fromhex(cypher_text)

    # Alle möglichen Schlüssel durchprobieren (0-255)
    for key in range(256):
        if filter_non_ascii:
            plaintext = decrypt_xor(ciphertext, key)
            if all(
                    32 <= ord(c) <= 126 or ord(c) in [10, 13] for c in plaintext
            ):  # Prüfen auf druckbare ASCII-Zeichen
                print(f"Schlüssel {key}: {plaintext}")
        else:
            print(f"Schlüssel {key}: {decrypt_xor(ciphertext, key)}")


# Does execute xor_bitwise computation on two integers (either decimal or binary)
def xor_bitwise(a: int, b: int, as_binary=False):
    if as_binary:
        return bin(a ^ b)
    else:
        return a ^ b


# Helper function to check if a number is prime or not
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


# Generates a prime number in a given range
def generate_prime(min_val, max_val):
    prime = random.randrange(min_val, max_val)
    while not is_prime(prime):
        prime = random.randrange(min_val, max_val)
    return prime


# Mod inverse using the extended Euclidean algorithm
def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, x, _ = extended_gcd(e, phi)
    return (x % phi + phi) % phi


# Generates a RSA keypair
def generate_rsa_keypair(p=generate_prime(10, 1000), q=generate_prime(10, 1000), e=0):
    n = p * q

    print(f"N: {n}")

    phi = (p - 1) * (q - 1)
    print(f"Phi: {phi}")

    if e == 0:
        e = random.randrange(1, phi)
        while math.gcd(e, phi) != 1:
            e = random.randrange(1, phi)
    d = mod_inverse(e, phi)

    print(f"Mod inverse: {d}")
    print(f"Public key: ({e, n})")
    print(f"Private key: ({d, n})")

    return (e, n), (d, n)


def rsa_encrypt_decrypt(message: int, key: tuple):
    key, n = key
    output = pow(message, key, n)
    print(f"Original message: {message}")
    print(f"Encrypted/Decrypted with ({key}): {output}")
    return pow(message, key, n)


# Creates the diffie hellman key exchange
def diffie_hellman(g: int, p: int, alice_private: int, bob_private: int) -> tuple:
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)

    secret_alice = pow(bob_public, alice_private, p)
    secret_bob = pow(alice_public, bob_private, p)

    assert (
            secret_alice == secret_bob
    ), "Fehler: Die berechneten Geheimnisse stimmen nicht überein!"

    print(f"Alice: {alice_public}, Bob: {bob_public}, Geheimnis: {secret_alice}")

    return alice_public, bob_public, secret_alice


# Brute force the private key of Alice by trying all possible values
def diffie_hellman_brute_force(g: int, p: int, alice_public: int) -> int:
    for i in range(1000):
        if pow(g, i, p) == alice_public:
            print(f"Alice's privater Schlüssel: {i}")
            return i


# calculate amount of additions, doubles and the operations for a scalar multiplication
def analyze_scalar_multiplication(number: int):
    binary = bin(number)[2:]
    print(binary)

    additions = 0
    doubles = 0
    operations = []

    # Analysiere jedes Bit von links nach rechts
    current_value = 0
    for i, bit in enumerate(binary):
        # Wenn wir nicht beim ersten Bit sind, müssen wir verdoppeln
        if i > 0:
            doubles += 1
            current_value *= 2
            operations.append(f"Verdoppele {current_value // 2} -> {current_value}")

        # Wenn das aktuelle Bit 1 ist, müssen wir addieren
        if bit == "1":
            if i > 0:  # Beim ersten 1-Bit müssen wir nicht addieren
                additions += 1
                operations.append(f"Addiere 1 -> {current_value + 1}")
            current_value += 1

    print(f"Additionen: {additions}, Verdopplungen: {doubles}")

    return additions, doubles, operations


def calculate_amount_key_exchanges_symmetric(n: int):
    return (n * (n - 1)) / 2


def calculate_amount_key_exchanges_asymmetric(n: int):
    return n


def generate_tbs_hash():
    """
    Generate the TBS hash of the certificate (ca_cert.pem file) using SHA256
    """
    with open("ca_cert.pem", "rb") as f:
        certificate_pem = f.read()

    # calculate sha256 fingerprint on "to be signed" part of certificate

    certificate = x509.load_pem_x509_certificate(certificate_pem)

    # Get the part of the certificate which we want to hash, is already in DER encoding internally
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


def generate_certificate_hash():
    """
    Generate the SHA1 fingerprint of the whole certificate (ca_cert.pem file)
    :return:
    """
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


def get_headers_of_url(url: str):
    """
    Get the headers of a URL
    :param url: The URL to get the headers from
    """
    response = requests.head(url)
    headers = response.headers

    for key, value in headers.items():
        print(f"{key}: {value}")


def hotp(secret: str, count: int, digits=6):
    """
    Generate a HOTP code based on the secret and counter
    :param secret: The secret key (in string format) --> DO NOT INPUT A BASE32 STRING
    :param count: The counter value
    :param digits: The number of digits of the code
    :return:
    """
    # Convert counter to 8-byte big-endian representation
    counter = count.to_bytes(8, byteorder="big")
    # Create HMAC-SHA1 hash
    hasher = hmac.new(bytes(secret.encode()), counter, hashlib.sha1)
    hmac_hash = bytearray(hasher.digest())
    # Get offset based on last nibble
    offset = hmac_hash[-1] & 0xF
    # Generate 4-byte code using offset
    code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
    )
    # Return truncated code
    return code % (10 ** digits)


def totp(secret: str, time_step=30, digits=6, unix_timestamp=int(time.time())):
    """
    Generate a TOTP code based on the secret and the current time
    :param secret: The secret key (in string format) --> DO NOT INPUT A BASE32 STRING
    :param time_step: The time step in seconds
    :param digits: The number of digits of the code
    :param unix_timestamp: The timestamp to use
    :return:
    """
    # Calculate counter based on current time and time step
    counter = unix_timestamp // time_step
    # Generate HOTP code
    return hotp(secret, counter, digits)

# TODO MAIL
