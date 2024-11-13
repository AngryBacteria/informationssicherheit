import math
import random
from math import log2, ceil
from typing import Union, Literal

NumberSystem = Literal["hex", "dec", "bin", "oct"]


def convert_number(
        number: Union[str, int], from_system: NumberSystem, to_system: NumberSystem
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


def password_possibilities(length: int, unique_characters: int) -> int:
    return unique_characters ** length


def password_entropy(length: int, unique_characters: int, ceil_value=True) -> float:
    value = length * log2(unique_characters)
    if ceil_value:
        return ceil(value)
    return value


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


def generate_check_digit(partial_number: str | int) -> str:
    partial_number = str(partial_number)
    for check_digit in range(10):
        if is_valid_luhn(partial_number + str(check_digit)):
            return partial_number + str(check_digit)


def linear_congruential_generator(init_x: int, a=6, b=0, m=13, n=1):
    output = []
    x = init_x
    for _ in range(n):
        output.append(x)
        x = (a * x + b) % m
    return output


# TODO: understand
def decrypt_xor(ciphertext: bytes, key: int):
    return "".join(chr(c ^ key) for c in ciphertext)


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


def xor_bitwise(a: int, b: int, as_binary=False):
    if as_binary:
        return bin(a ^ b)
    else:
        return a ^ b


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(min_val, max_val):
    prime = random.randrange(min_val, max_val)
    while not is_prime(prime):
        prime = random.randrange(min_val, max_val)
    return prime


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


def generate_keypair(p=generate_prime(10, 1000), q=generate_prime(10, 1000), e=0):
    n = p * q
    phi = (p - 1) * (q - 1)
    if e == 0:
        e = random.randrange(1, phi)
        while math.gcd(e, phi) != 1:
            e = random.randrange(1, phi)
    d = mod_inverse(e, phi)
    return (e, n), (d, n)
