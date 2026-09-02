#---------------------------------------------------------------------------------
#Testing Digital Signature Authentication
#---------------------------------------------------------------------------------
# This program receives the message, signature, and Leader's public key. It uses the
# public key to verify the digital signature. If the signature is valid, the follower
# knows that the message was signed by the Leader's private key and can be trusted.
#
# This file only tests digital signature authentication. No drones are connected or
# flown during this test.
#---------------------------------------------------------------------------------




import socket

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


LOCAL_IP = "127.0.0.1"
PORT = 7000


def main():

    print("\n================================")
    print("FOLLOWER - DIGITAL SIGNATURE TEST")
    print("================================")

    # UDP socket

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (
            LOCAL_IP,
            PORT
        )
    )

    print("\nWaiting for Leader message...")

    packet, address = sock.recvfrom(
        4096
    )

    print("Message received.")

    # Extract public key length

    public_key_length = int.from_bytes(
        packet[0:2],
        "big"
    )

    start = 2

    end = start + public_key_length

    public_key_bytes = packet[start:end]

    # Extract signature

    signature_length = int.from_bytes(
        packet[end:end + 2],
        "big"
    )

    signature_start = end + 2

    signature_end = (
        signature_start
        + signature_length
    )

    signature = packet[
        signature_start:signature_end
    ]

    # Extract message

    message = packet[
        signature_end:
    ]

    print("\nReceived message:")
    print(message.decode())

    # Convert Leader public key

    leader_public_key = (
        ec.EllipticCurvePublicKey
        .from_encoded_point(
            ec.SECP256R1(),
            public_key_bytes
        )
    )

    print(
        "\nLeader public key received."
    )

    # VERIFY SIGNATURE

    print(
        "\nVerifying digital signature..."
    )

    try:

        leader_public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

        print("\n================================")
        print("SIGNATURE VALID!")
        print("================================")

        print(
            "The message was signed using the "
            "matching Leader private key."
        )

        print(
            "\nAuthentication SUCCESS."
        )

    except InvalidSignature:

        print("\n================================")
        print("SECURITY ALERT!")
        print("================================")

        print(
            "SIGNATURE INVALID!"
        )

        print(
            "The message cannot be trusted."
        )

    sock.close()


if __name__ == "__main__":
    main()