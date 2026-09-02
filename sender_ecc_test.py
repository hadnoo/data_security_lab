#---------------------------------------------------------------------------------------------------
#Test the security of the ECC key exchange.
#---------------------------------------------------------------------------------------------------
#This program creates a normal ECC public key and then deliberately modifies it to make it invalid.
#The invalid key is sent to the follower to test whether the follower can detect the problem.
#This test does not involve any drone flight. We only test ECC security.
#---------------------------------------------------------------------------------------------------



import socket
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


# CONFIGURATION

LOCAL_IP = "127.0.0.1"

ECC_LEADER_PORT = 6000
ECC_FOLLOWER_PORT = 6001


# CREATE AND SEND INVALID ECC PUBLIC KEY

def main():

    print("\n================================")
    print("STARTING ECC SECURITY TEST")
    print("LEADER / SENDER")
    print("================================")

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (
            LOCAL_IP,
            ECC_LEADER_PORT
        )
    )

    print("\nCreating a normal ECC key pair...")

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    print(
        f"Normal ECC public key length: "
        f"{len(public_bytes)} bytes"
    )

    print("\n--------------------------------")
    print("SECURITY TEST")
    print("--------------------------------")

    # CREATE A DEFINITELY INVALID ECC PUBLIC KEY
    #
    # For an uncompressed SECP256R1 point:
    # First byte must normally be 0x04.
    #
    # We deliberately replace it with 0x00.

    invalid_public_key = bytearray(
        public_bytes
    )

    invalid_public_key[0] = 0x00

    invalid_public_key = bytes(
        invalid_public_key
    )

    print(
        "ECC public key deliberately modified."
    )

    print(
        "Invalid public key will be sent "
        "to the follower."
    )

    print("--------------------------------")

    time.sleep(2)

    # SEND INVALID KEY

    sock.sendto(
        invalid_public_key,
        (
            LOCAL_IP,
            ECC_FOLLOWER_PORT
        )
    )

    print(
        "\nInvalid ECC public key sent."
    )

    print(
        "Waiting for follower response..."
    )

    sock.settimeout(10)

    try:

        response, address = sock.recvfrom(
            1024
        )

        print(
            "\nFollower response received:"
        )

        print(
            response.decode()
        )

    except socket.timeout:

        print(
            "\nNo response received from follower."
        )

    finally:

        sock.close()

    print("\n================================")
    print("ECC TEST FINISHED")
    print("NO DRONE FLIGHT WAS STARTED")
    print("================================")


if __name__ == "__main__":
    main()