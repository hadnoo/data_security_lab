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
import os

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


# CONFIGURATION

LEADER_URI = "radio://0/80/2M/E7E7E7E711"

LOCAL_IP = "127.0.0.1"

ECC_LEADER_PORT = 6000
ECC_FOLLOWER_PORT = 6001

POSITION_PORT = 5005


# FLIGHT SETTINGS

FLIGHT_HEIGHT = 0.30
TAKEOFF_TIME = 2.0
LEADER_MOVE_TIME = 3.0
LAND_TIME = 2.0


# CORNERS

CORNER_1 = (-0.20, -0.59, 0.30)
CORNER_2 = (0.57, -0.51, 0.30)
CORNER_3 = (0.54, 0.25, 0.30)
CORNER_4 = (-0.34, 0.08, 0.30)


# PREPARE DRONE

def prepare_drone(cf, name):

    print(f"\nPreparing {name}...")

    try:
        cf.param.set_value(
            "commander.enHighLevel",
            "1"
        )

        time.sleep(1)

    except Exception as error:
        print("Warning:", error)

    print(f"Arming {name}...")

    cf.supervisor.send_arming_request(True)

    time.sleep(2)

    print(f"{name} arm request sent.")


# LOAD PERMANENT SIGNING PRIVATE KEY

def load_signing_private_key():

    with open(
        "leader_signing_private_key.pem",
        "rb"
    ) as f:

        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    return private_key


# AUTHENTICATED ECDH KEY EXCHANGE

def create_authenticated_aes_key(sock):

    print("\n================================")
    print("AUTHENTICATED ECC KEY EXCHANGE")
    print("LEADER")
    print("================================")

    # Permanent signing key

    signing_private_key = (
        load_signing_private_key()
    )

    # Temporary ECDH key

    ecdh_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    ecdh_public_key = (
        ecdh_private_key.public_key()
    )

    ecdh_public_bytes = (
        ecdh_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    )

    # SIGN ECDH PUBLIC KEY

    signature = signing_private_key.sign(
        ecdh_public_bytes,
        ec.ECDSA(hashes.SHA256())
    )

    print(
        "Temporary ECDH public key created."
    )

    print(
        "ECDH public key signed using "
        "Leader's permanent private key."
    )

    # Packet:
    #
    # [2 bytes ECDH key length]
    # [ECDH public key]
    # [2 bytes signature length]
    # [signature]

    packet = (
        len(ecdh_public_bytes).to_bytes(
            2,
            "big"
        )
        + ecdh_public_bytes
        + len(signature).to_bytes(
            2,
            "big"
        )
        + signature
    )

    # SEND TO FOLLOWER

    sock.sendto(
        packet,
        (
            LOCAL_IP,
            ECC_FOLLOWER_PORT
        )
    )

    print(
        "Signed ECDH public key sent."
    )

    # RECEIVE FOLLOWER ECDH PUBLIC KEY

    print(
        "Waiting for follower ECDH public key..."
    )

    follower_public_bytes, address = (
        sock.recvfrom(1024)
    )

    follower_public_key = (
        ec.EllipticCurvePublicKey
        .from_encoded_point(
            ec.SECP256R1(),
            follower_public_bytes
        )
    )

    print(
        "Follower ECDH public key received."
    )

    # CREATE SHARED SECRET

    shared_secret = ecdh_private_key.exchange(
        ec.ECDH(),
        follower_public_key
    )

    # DERIVE AES-256 KEY

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


# SEND ENCRYPTED POSITION

def send_position(
    sock,
    aes,
    position,
    name
):

    data = json.dumps(
        {
            "x": position[0],
            "y": position[1],
            "z": position[2]
        }
    ).encode()

    nonce = os.urandom(12)

    encrypted_data = aes.encrypt(
        nonce,
        data,
        None
    )

    message = nonce + encrypted_data

    sock.sendto(
        message,
        (
            LOCAL_IP,
            POSITION_PORT
        )
    )

    print(
        f"Encrypted position sent: {name}"
    )


# MOVE LEADER AND SEND OLD POSITION

def move_and_send_old_position(
    commander,
    position_sock,
    aes,
    old_position,
    old_name,
    new_position,
    new_name
):

    print(
        f"\nLeader leaving {old_name}"
    )

    print(
        f"Leader going to {new_name}"
    )

    commander.go_to(
        new_position[0],
        new_position[1],
        new_position[2],
        0,
        LEADER_MOVE_TIME,
        relative=False
    )

    # Give leader time to leave
    time.sleep(0.8)

    send_position(
        position_sock,
        aes,
        old_position,
        old_name
    )

    time.sleep(
        LEADER_MOVE_TIME + 0.7
    )


# MAIN

def main():

    print("\nSTARTING LEADER AUTH VERSION")

    cflib.crtp.init_drivers()

    # ECC socket
    ecc_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    ecc_sock.bind(
        (
            LOCAL_IP,
            ECC_LEADER_PORT
        )
    )

    # Authenticated ECC exchange
    aes_key = create_authenticated_aes_key(
        ecc_sock
    )

    aes = AESGCM(aes_key)

    print(
        "\nAUTHENTICATED ECC SUCCESS!"
    )

    # Position socket
    position_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    cf = Crazyflie(
        rw_cache="./cache_sender_auth"
    )

    try:

        with SyncCrazyflie(
            LEADER_URI,
            cf=cf
        ) as scf:

            print(
                "Leader connected!"
            )

            prepare_drone(
                scf.cf,
                "Leader"
            )

            commander = (
                scf.cf.high_level_commander
            )

            # Wait for follower
            print(
                "\nWaiting for follower..."
            )

            message, address = (
                ecc_sock.recvfrom(1024)
            )

            if message != b"FOLLOWER_READY":

                print(
                    "Follower not ready!"
                )

                return

            # TAKEOFF
            commander.takeoff(
                FLIGHT_HEIGHT,
                TAKEOFF_TIME
            )

            time.sleep(
                TAKEOFF_TIME + 1
            )

            # GO TO CORNER 1

            commander.go_to(
                CORNER_1[0],
                CORNER_1[1],
                CORNER_1[2],
                0,
                LEADER_MOVE_TIME,
                relative=False
            )

            time.sleep(
                LEADER_MOVE_TIME + 0.7
            )

            # Square

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_1,
                "CORNER 1",
                CORNER_2,
                "CORNER 2"
            )

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_2,
                "CORNER 2",
                CORNER_3,
                "CORNER 3"
            )

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_3,
                "CORNER 3",
                CORNER_4,
                "CORNER 4"
            )

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_4,
                "CORNER 4",
                CORNER_1,
                "CORNER 1"
            )

            # Final movement

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_1,
                "CORNER 1 FINAL",
                CORNER_2,
                "CORNER 2 FINAL"
            )

            # LAND LEADER

            print(
                "\nLeader landing..."
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
            "\nLEADER ERROR:"
        )

        print(error)

    finally:

        ecc_sock.close()
        position_sock.close()


if __name__ == "__main__":
    main()