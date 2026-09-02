#-----------------------------------------------------------------------------------------
#Tested manipulation of AES-GCM messages.
#-----------------------------------------------------------------------------------------
#This program controls the leader drone and sends encrypted position data to the follower. 
# During the security test, the message containing Corner 3 is intentionally modified to 
# simulate a tampering attack. The purpose is to test whether the receiver can detect the 
# manipulated message.
#-----------------------------------------------------------------------------------------

import time
import json
import socket
import os

import cflib.crtp
from cflib.crazyflie import Crazyflie
from cflib.crazyflie.syncCrazyflie import SyncCrazyflie

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
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


# YOUR MEASURED CORNERS

CORNER_1 = (-0.20, -0.59, 0.30)

CORNER_2 = (0.57, -0.51, 0.30)

CORNER_3 = (0.54, 0.25, 0.30)

CORNER_4 = (-0.34, 0.08, 0.30)


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

        print("High Level Commander enabled.")

    except Exception as error:

        print("WARNING:")
        print(error)

    print(f"Sending ARM request to {name}...")

    cf.supervisor.send_arming_request(True)

    time.sleep(2.0)

    print(f"ARM request sent to {name}.")

    print("================================\n")


# ECC KEY EXCHANGE

def create_aes_key(sock):

    print("\n================================")
    print("ECC KEY EXCHANGE - LEADER")
    print("================================")

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    leader_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    sock.sendto(
        leader_public_bytes,
        (
            LOCAL_IP,
            ECC_FOLLOWER_PORT
        )
    )

    print("Leader ECC public key sent.")

    print("Waiting for follower ECC public key...")

    follower_public_bytes, address = sock.recvfrom(1024)

    print("Follower ECC public key received.")

    follower_public_key = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            follower_public_bytes
        )
    )

    shared_secret = private_key.exchange(
        ec.ECDH(),
        follower_public_key
    )

    print("ECC shared secret created.")

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Crazyflie-ECC-AES"
    ).derive(
        shared_secret
    )

    print("AES-256 session key generated.")

    print("================================\n")

    return aes_key


# SEND ENCRYPTED POSITION

def send_position(
    sock,
    aes,
    position,
    name,
    tamper=False
):

    data = json.dumps(
        {
            "x": position[0],
            "y": position[1],
            "z": position[2]
        }
    ).encode()

    # Unique AES-GCM nonce
    nonce = os.urandom(12)

    encryption_start = time.perf_counter()

    encrypted_data = aes.encrypt(
        nonce,
        data,
        None
    )

    encryption_time = (
        time.perf_counter()
        - encryption_start
    ) * 1000

    # SECURITY TEST:
    # MODIFY THE ENCRYPTED MESSAGE

    if tamper:

        encrypted_list = bytearray(
            encrypted_data
        )

        # Change one bit
        encrypted_list[0] ^= 0x01

        encrypted_data = bytes(
            encrypted_list
        )

        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("SECURITY TEST!")
        print("Encrypted message was modified!")
        print("AES-GCM should reject it!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    # Message contains:
    #
    # [12 byte nonce][encrypted data + authentication tag]

    message = nonce + encrypted_data

    sock.sendto(
        message,
        (
            LOCAL_IP,
            POSITION_PORT
        )
    )

    print("\n--------------------------------")
    print(f"POSITION SENT: {name}")
    print("--------------------------------")
    print("Original position:", position)
    print("AES-GCM encryption completed.")
    print(
        f"Encryption time: "
        f"{encryption_time:.3f} ms"
    )
    print("--------------------------------")


# MOVE LEADER + SEND OLD POSITION

def move_and_send_old_position(
    commander,
    position_sock,
    aes,
    old_position,
    old_name,
    new_position,
    new_name,
    tamper=False
):

    print("\n================================")
    print(f"LEADER LEAVING {old_name}")
    print(f"LEADER GOING TO {new_name}")
    print("================================")

    # Start moving leader away first
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

    # Send old position to follower
    send_position(
        position_sock,
        aes,
        old_position,
        old_name,
        tamper
    )

    # Wait for leader movement
    time.sleep(
        LEADER_MOVE_TIME + 0.7
    )

    print(
        f"Leader reached {new_name}."
    )


# MAIN

def main():

    print("\n================================")
    print("STARTING LEADER SECURITY TEST")
    print("================================")

    cflib.crtp.init_drivers()

    # ECC SOCKET

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

    # ECC + AES key generation
    aes_key = create_aes_key(
        ecc_sock
    )

    aes = AESGCM(
        aes_key
    )

    print("ECC exchange completed successfully.")

    # POSITION SOCKET

    position_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    # CONNECT TO LEADER

    print("\nConnecting to leader drone...")
    print(LEADER_URI)

    cf = Crazyflie(
        rw_cache="./cache_sender"
    )

    try:

        with SyncCrazyflie(
            LEADER_URI,
            cf=cf
        ) as scf:

            print("\nLEADER DRONE CONNECTED!")

            # ARM
            prepare_drone(
                scf.cf,
                "Leader drone"
            )

            commander = (
                scf.cf.high_level_commander
            )

            # WAIT FOR FOLLOWER

            print(
                "\nWaiting for follower READY signal..."
            )

            ecc_sock.settimeout(30)

            try:

                message, address = (
                    ecc_sock.recvfrom(1024)
                )

                if message == b"FOLLOWER_READY":

                    print(
                        "FOLLOWER IS READY!"
                    )

                else:

                    print(
                        "Unknown message received."
                    )

            except socket.timeout:

                print(
                    "ERROR: Follower was not ready."
                )

                return

            finally:

                ecc_sock.settimeout(None)

            # TAKE OFF

            print("\nLEADER TAKING OFF...")

            commander.takeoff(
                FLIGHT_HEIGHT,
                TAKEOFF_TIME
            )

            time.sleep(
                TAKEOFF_TIME + 1.0
            )

            # GO TO CORNER 1

            print(
                "\nLEADER GOING TO CORNER 1"
            )

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

            # CORNER 1 → CORNER 2
            #
            # Send Corner 1 normally

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_1,
                "CORNER 1",
                CORNER_2,
                "CORNER 2"
            )

            # CORNER 2 → CORNER 3
            #
            # Send Corner 2 normally

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_2,
                "CORNER 2",
                CORNER_3,
                "CORNER 3"
            )

            # CORNER 3 → CORNER 4
            #
            # SECURITY TEST:
            # Corner 3 encrypted message is modified!

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_3,
                "CORNER 3 - TAMPERED TEST",
                CORNER_4,
                "CORNER 4",
                tamper=True
            )

            # CORNER 4 → CORNER 1
            #
            # Send Corner 4 normally

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_4,
                "CORNER 4",
                CORNER_1,
                "CORNER 1"
            )

            # FINAL:
            # CORNER 1 → CORNER 2
            #
            # Send Corner 1 normally

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_1,
                "CORNER 1 FINAL",
                CORNER_2,
                "CORNER 2 FINAL LANDING"
            )

            # LAND LEADER

            print("\n================================")
            print("LEADER LANDING AT CORNER 2")
            print("================================")

            time.sleep(1)

            commander.land(
                0.0,
                LAND_TIME
            )

            time.sleep(
                LAND_TIME + 1.0
            )

            commander.stop()

            print(
                "\nLEADER LANDED SUCCESSFULLY."
            )

    except Exception as error:

        print("\n================================")
        print("LEADER ERROR")
        print("================================")
        print(error)

    finally:

        ecc_sock.close()
        position_sock.close()

        print(
            "\nLeader program finished."
        )



if __name__ == "__main__":
    main()