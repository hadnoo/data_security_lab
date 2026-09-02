#---------------------------------------------------------------------------------
# Final Authentication and Secure Communication
#---------------------------------------------------------------------------------
# In the previous leader_signature_test.py and follower_signature_test.py files,
# we tested how digital signatures work without connecting or flying any drones.
# The Leader also created a new signing key pair every time the program was run.
#
# In these final files, digital signature authentication is integrated into the
# actual drone communication system. The Leader now uses permanent signing keys
# stored in .pem files.
#---------------------------------------------------------------------------------




import time
import json
import socket

import cflib.crtp
from cflib.crazyflie import Crazyflie
from cflib.crazyflie.syncCrazyflie import SyncCrazyflie

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import (
    serialization,
    hashes
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# CONFIGURATION

FOLLOWER_URI = "radio://1/100/2M/E7E7E7E710"

LOCAL_IP = "127.0.0.1"

ECC_LEADER_PORT = 6000
ECC_FOLLOWER_PORT = 6001

POSITION_PORT = 5005


# FLIGHT SETTINGS

FLIGHT_HEIGHT = 0.30
TAKEOFF_TIME = 2.0
FOLLOWER_MOVE_TIME = 2.5
LAND_TIME = 2.0


# PREPARE DRONE

def prepare_drone(cf, name):

    print(
        f"\nPreparing {name}..."
    )

    try:

        cf.param.set_value(
            "commander.enHighLevel",
            "1"
        )

        time.sleep(1)

    except Exception as error:

        print(
            "Warning:",
            error
        )

    print(
        f"Arming {name}..."
    )

    cf.supervisor.send_arming_request(
        True
    )

    time.sleep(2)

    print(
        f"{name} arm request sent."
    )


# LOAD TRUSTED LEADER PUBLIC KEY

def load_trusted_leader_public_key():

    with open(
        "leader_signing_public_key.pem",
        "rb"
    ) as f:

        public_key = (
            serialization.load_pem_public_key(
                f.read()
            )
        )

    return public_key


# AUTHENTICATED ECDH EXCHANGE

def create_authenticated_aes_key(sock):

    print("\n================================")
    print("AUTHENTICATED ECC KEY EXCHANGE")
    print("FOLLOWER")
    print("================================")

    # Load trusted Leader signing public key

    trusted_leader_public_key = (
        load_trusted_leader_public_key()
    )

    print(
        "Trusted Leader public key loaded."
    )

    # Receive signed packet

    print(
        "Waiting for signed ECDH public key..."
    )

    packet, address = sock.recvfrom(
        2048
    )

    # Extract ECDH key

    ecdh_key_length = int.from_bytes(
        packet[0:2],
        "big"
    )

    key_start = 2
    key_end = (
        key_start + ecdh_key_length
    )

    leader_ecdh_public_bytes = (
        packet[key_start:key_end]
    )

    # Extract signature

    signature_length = int.from_bytes(
        packet[key_end:key_end + 2],
        "big"
    )

    signature_start = key_end + 2

    signature_end = (
        signature_start
        + signature_length
    )

    signature = packet[
        signature_start:signature_end
    ]

    # VERIFY SIGNATURE

    print(
        "\nVerifying Leader signature..."
    )

    try:

        trusted_leader_public_key.verify(
            signature,
            leader_ecdh_public_bytes,
            ec.ECDSA(
                hashes.SHA256()
            )
        )

        print(
            "\nSIGNATURE VALID!"
        )

        print(
            "Leader authenticated successfully."
        )

    except InvalidSignature:

        print("\n================================")
        print("SECURITY ALERT!")
        print("================================")

        print(
            "INVALID LEADER SIGNATURE!"
        )

        print(
            "Leader cannot be authenticated."
        )

        print(
            "NO AES KEY WILL BE CREATED."
        )

        print(
            "DRONES WILL NOT FLY."
        )

        print("================================")

        return None

    # Convert Leader ECDH public key

    leader_ecdh_public_key = (
        ec.EllipticCurvePublicKey
        .from_encoded_point(
            ec.SECP256R1(),
            leader_ecdh_public_bytes
        )
    )

    # Create temporary Follower ECDH key

    follower_private_key = (
        ec.generate_private_key(
            ec.SECP256R1()
        )
    )

    follower_public_key = (
        follower_private_key.public_key()
    )

    follower_public_bytes = (
        follower_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    )

    # Send follower ECDH public key
    sock.sendto(
        follower_public_bytes,
        (
            LOCAL_IP,
            ECC_LEADER_PORT
        )
    )

    # CREATE SHARED SECRET

    shared_secret = (
        follower_private_key.exchange(
            ec.ECDH(),
            leader_ecdh_public_key
        )
    )

    # DERIVE AES KEY

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Crazyflie-ECC-AES-AUTH"
    ).derive(
        shared_secret
    )

    print(
        "Authenticated shared secret created."
    )

    print(
        "AES-256 session key generated."
    )

    return aes_key


# RECEIVE AND DECRYPT POSITION

def receive_position(sock, aes):

    message, address = sock.recvfrom(
        1024
    )

    nonce = message[:12]

    encrypted_data = message[12:]

    decrypted_data = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    position = json.loads(
        decrypted_data.decode()
    )

    print(
        "\nDecrypted position:",
        position
    )

    return (
        position["x"],
        position["y"],
        position["z"]
    )


# MAIN

def main():

    print(
        "\nSTARTING FOLLOWER AUTH VERSION"
    )

    cflib.crtp.init_drivers()

    # ECC SOCKET

    ecc_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    ecc_sock.bind(
        (
            LOCAL_IP,
            ECC_FOLLOWER_PORT
        )
    )

    # AUTHENTICATED ECC EXCHANGE

    aes_key = create_authenticated_aes_key(
        ecc_sock
    )

    # Stop immediately if authentication failed
    if aes_key is None:

        print(
            "\nAuthentication failed."
        )

        print(
            "Follower will not connect "
            "or fly."
        )

        ecc_sock.close()

        return

    aes = AESGCM(
        aes_key
    )

    print(
        "\nAUTHENTICATED ECC SUCCESS!"
    )

    # POSITION SOCKET

    position_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    position_sock.bind(
        (
            LOCAL_IP,
            POSITION_PORT
        )
    )

    # READY SOCKET

    ready_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    cf = Crazyflie(
        rw_cache="./cache_receiver_auth"
    )

    try:

        with SyncCrazyflie(
            FOLLOWER_URI,
            cf=cf
        ) as scf:

            print(
                "\nFollower connected!"
            )

            prepare_drone(
                scf.cf,
                "Follower"
            )

            commander = (
                scf.cf.high_level_commander
            )

            # TAKEOFF

            commander.takeoff(
                FLIGHT_HEIGHT,
                TAKEOFF_TIME
            )

            time.sleep(
                TAKEOFF_TIME + 1
            )

            # READY SIGNAL

            ready_sock.sendto(
                b"FOLLOWER_READY",
                (
                    LOCAL_IP,
                    ECC_LEADER_PORT
                )
            )

            print(
                "Follower ready."
            )

            # RECEIVE 5 POSITIONS

            for i in range(5):

                print(
                    f"\nWaiting for position "
                    f"{i + 1}/5..."
                )

                x, y, z = receive_position(
                    position_sock,
                    aes
                )

                print(
                    f"Follower going to: "
                    f"{x}, {y}, {z}"
                )

                commander.go_to(
                    x,
                    y,
                    z,
                    0,
                    FOLLOWER_MOVE_TIME,
                    relative=False
                )

                time.sleep(
                    FOLLOWER_MOVE_TIME + 0.5
                )

            # LAND

            print(
                "\nFollower landing..."
            )

            commander.land(
                0.0,
                LAND_TIME
            )

            time.sleep(
                LAND_TIME + 1
            )

            commander.stop()

    except Exception as error:

        print(
            "\nFOLLOWER ERROR:"
        )

        print(error)

    finally:

        ecc_sock.close()
        position_sock.close()
        ready_sock.close()


if __name__ == "__main__":
    main()