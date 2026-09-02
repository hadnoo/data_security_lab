#---------------------------------------------------------------------------------
#Testing Digital Signature Authentication
#---------------------------------------------------------------------------------
#This program creates a message and signs it using the Leader's private key. It then 
#sends the message, the digital signature, and the Leader's public key to the follower. 
#The purpose is to prove that the message was created by the real Leader.
#The Leader generates a new key pair every time the program runs.
#This file only tests digital signature authentication. No drones are connected or 
#flown during this test.
#---------------------------------------------------------------------------------




import socket

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


LOCAL_IP = "127.0.0.1"
PORT = 7000


def main():

    print("\n================================")
    print("LEADER - DIGITAL SIGNATURE TEST")
    print("================================")

    # 1. Create Leader's signing key pair

    leader_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    leader_public_key = leader_private_key.public_key()

    print("\nLeader created signing key pair.")

    # 2. Create a message

    message = b"Hello, I am the real Leader."

    print("\nMessage:")
    print(message.decode())

    # 3. Sign message using Leader's PRIVATE key

    signature = leader_private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    print("\nMessage signed using Leader's PRIVATE key.")

    # 4. Convert public key to bytes

    public_key_bytes = leader_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Send:
    #
    # [public key length]
    # [public key]
    # [signature]
    # [message]
    #
    # For this simple test we use JSON-like packet lengths.

    packet = (
        len(public_key_bytes).to_bytes(2, "big")
        + public_key_bytes
        + len(signature).to_bytes(2, "big")
        + signature
        + message
    )

    # UDP socket

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    print("\nSending message + signature + public key...")

    sock.sendto(
        packet,
        (
            LOCAL_IP,
            PORT
        )
    )

    print("Sent successfully.")

    sock.close()


if __name__ == "__main__":
    main()