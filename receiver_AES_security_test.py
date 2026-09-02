#--------------------------------------------------------------------------------
#Tested manipulation of AES-GCM messages.
#--------------------------------------------------------------------------------
# This program controls the follower drone and receives the encrypted position data.
# It attempts to decrypt and verify each message using AES-GCM. Valid positions are 
# accepted and followed, while the intentionally modified Corner 3 message fails 
# authentication and is rejected, so the follower does not fly to that position.
#---------------------------------------------------------------------------------


import time
import json
import socket

import cflib.crtp
from cflib.crazyflie import Crazyflie
from cflib.crazyflie.syncCrazyflie import SyncCrazyflie

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


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


# ARM + ENABLE HIGH LEVEL COMMANDER

def prepare_drone(cf, name):

    print("\n================================")
    print(f"PREPARING {name.upper()}")
    print("================================")

    print("Enabling High Level Commander...")

    try:

        cf.param.set_value(
            "commander.enHighLevel",
            "1"
        )

        time.sleep(1.0)

        print(
            "High Level Commander enabled."
        )

    except Exception as error:

        print("WARNING:")
        print(error)

    # ARM BRUSHLESS CRAZYFLIE

    print(
        f"Sending ARM request to {name}..."
    )

    cf.supervisor.send_arming_request(True)

    time.sleep(2.0)

    print(
        f"ARM request sent to {name}."
    )

    print("================================\n")


# ECC KEY EXCHANGE

def create_aes_key(sock):

    print("\n================================")
    print("ECC KEY EXCHANGE - FOLLOWER")
    print("================================")

    # Generate ECC key pair
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    print(
        "Waiting for leader ECC public key..."
    )

    # Receive leader public key
    leader_public_bytes, address = (
        sock.recvfrom(1024)
    )

    print(
        "Leader ECC public key received."
    )

    leader_public_key = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            leader_public_bytes
        )
    )

    # Convert follower public key to bytes
    follower_public_bytes = (
        public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    )

    # Send follower public key
    sock.sendto(
        follower_public_bytes,
        (
            LOCAL_IP,
            ECC_LEADER_PORT
        )
    )

    print(
        "Follower ECC public key sent."
    )

    # Create shared secret
    shared_secret = private_key.exchange(
        ec.ECDH(),
        leader_public_key
    )

    print(
        "ECC shared secret created."
    )

    # Create AES-256 key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Crazyflie-ECC-AES"
    ).derive(
        shared_secret
    )

    print(
        "AES-256 session key generated."
    )

    print("================================\n")

    return aes_key


# RECEIVE + DECRYPT POSITION

def receive_position(sock, aes):

    print(
        "\nWaiting for encrypted position..."
    )

    message, address = sock.recvfrom(
        1024
    )

    # First 12 bytes = nonce
    nonce = message[:12]

    # Remaining bytes = ciphertext + authentication tag
    encrypted_data = message[12:]

    try:

        decryption_start = (
            time.perf_counter()
        )

        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )

        decryption_time = (
            time.perf_counter()
            - decryption_start
        ) * 1000

        position = json.loads(
            decrypted_data.decode()
        )

        print("\n--------------------------------")
        print("MESSAGE ACCEPTED")
        print("--------------------------------")

        print(
            "AES-GCM authentication: SUCCESS"
        )

        print(
            "Decrypted position:"
        )

        print(position)

        print(
            f"Decryption time: "
            f"{decryption_time:.3f} ms"
        )

        print("--------------------------------")

        return (
            position["x"],
            position["y"],
            position["z"]
        )

    # SECURITY:
    # AES-GCM detects modified messages

    except InvalidTag:

        print("\n================================")
        print("SECURITY ALERT!")
        print("================================")

        print(
            "AES-GCM authentication FAILED!"
        )

        print(
            "The message may have been modified "
            "or corrupted."
        )

        print(
            "POSITION REJECTED!"
        )

        print(
            "Follower will NOT fly to this position."
        )

        print("================================")

        return None

# MAIN

def main():

    print("\n================================")
    print(
        "STARTING FOLLOWER SECURITY TEST"
    )
    print("================================")

    # INITIALIZE CRAZYFLIE

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

    # ECC KEY EXCHANGE

    aes_key = create_aes_key(
        ecc_sock
    )

    aes = AESGCM(
        aes_key
    )

    ecc_sock.close()

    print(
        "ECC exchange completed successfully."
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

    # CONNECT TO FOLLOWER

    print(
        "\nConnecting to follower drone..."
    )

    print(FOLLOWER_URI)

    cf = Crazyflie(
        rw_cache="./cache_receiver"
    )

    try:

        with SyncCrazyflie(
            FOLLOWER_URI,
            cf=cf
        ) as scf:

            print("\n================================")
            print(
                "FOLLOWER DRONE CONNECTED!"
            )
            print("================================")

            # ARM

            prepare_drone(
                scf.cf,
                "Follower drone"
            )

            commander = (
                scf.cf.high_level_commander
            )

            # TAKEOFF

            print(
                "\nFOLLOWER TAKING OFF..."
            )

            commander.takeoff(
                FLIGHT_HEIGHT,
                TAKEOFF_TIME
            )

            time.sleep(
                TAKEOFF_TIME + 1.0
            )

            print(
                "Follower takeoff completed."
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
                "\nFollower is READY."
            )

            print(
                "Leader may now start."
            )

            # RECEIVE 5 MESSAGES

            for i in range(5):

                print(
                    "\n================================"
                )

                print(
                    f"WAITING FOR MESSAGE {i + 1}/5"
                )

                print(
                    "================================"
                )

                position = receive_position(
                    position_sock,
                    aes
                )

                # REJECTED MESSAGE

                if position is None:

                    print(
                        "\nMESSAGE REJECTED."
                    )

                    print(
                        "Follower remains at its "
                        "current safe position."
                    )

                    continue

                # ACCEPTED MESSAGE

                x, y, z = position

                print(
                    "\nFollower flying to:"
                )

                print(
                    f"x = {x}"
                )

                print(
                    f"y = {y}"
                )

                print(
                    f"z = {z}"
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

                print(
                    "\nFollower reached "
                    "accepted position."
                )

            # LAND FOLLOWER

            print("\n================================")
            print(
                "FOLLOWER FINISHED TEST"
            )
            print(
                "LANDING AT CURRENT POSITION"
            )
            print("================================")

            time.sleep(1.0)

            commander.land(
                0.0,
                LAND_TIME
            )

            time.sleep(
                LAND_TIME + 1.0
            )

            commander.stop()

            print(
                "\nFOLLOWER LANDED SUCCESSFULLY."
            )

    except Exception as error:

        print("\n================================")
        print("FOLLOWER ERROR")
        print("================================")

        print(error)

    finally:

        position_sock.close()

        ready_sock.close()

        print(
            "\nFollower program finished."
        )



if __name__ == "__main__":
    main()