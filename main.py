import math
import random
from math import log2, ceil
from typing import Union, Literal

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


# Calculate the number of possibilities for a password of a given length and number of unique characters
def password_possibilities(length: int, unique_characters: int) -> int:
    return unique_characters ** length


# Calculate the entropy of a password with a given length and number of unique characters
def password_entropy(length: int, unique_characters: int, ceil_value=True) -> float:
    value = length * log2(unique_characters)
    if ceil_value:
        return ceil(value)
    return value


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


# Checks if a digit is valid by the luhn algorithm
def generate_check_digit(partial_number: str | int) -> str:
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