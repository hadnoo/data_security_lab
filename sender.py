#------------------------------------------------------------------------------------------
# The sender program controls the leader drone. First, it performs an ECC/ECDH key exchange
# with the follower program. The shared secret is processed using HKDF to generate an AES-256
# session key. The leader drone is then armed and waits for the follower to be ready before
# taking off. The leader moves through the predefined corners and sends its previous position
# to the follower through UDP. Each position is encrypted using AES-GCM before being sent.
# Finally, the leader completes the flight path and lands at Corner 2.
#------------------------------------------------------------------------------------------

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


# MEASURED CORNERS

CORNER_1 = (
    -0.20,
    -0.59,
    0.30
)

CORNER_2 = (
    0.57,
    -0.51,
    0.30
)

CORNER_3 = (
    0.54,
    0.25,
    0.30
)

CORNER_4 = (
    -0.34,
    0.08,
    0.30
)

# ARM + ENABLE HIGH LEVEL COMMANDER

def prepare_drone(cf, name):

    print("\n================================")
    print(f"PREPARING {name.upper()}")
    print("================================")

    # Enable High Level Commander
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

        print(
            "WARNING: Could not explicitly enable "
            "commander.enHighLevel:"
        )

        print(error)

    # ARM BRUSHLESS CRAZYFLIE

    print(f"Sending ARM request to {name}...")

    cf.supervisor.send_arming_request(True)

    # Give Crazyflie time to arm
    time.sleep(2.0)

    print(
        f"ARM request sent to {name}."
    )

    print("================================\n")


# ECC KEY EXCHANGE

def create_aes_key(sock):

    print("\n================================")
    print("ECC KEY EXCHANGE - LEADER")
    print("================================")

    # Generate leader ECC private/public key pair
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    # Convert public key to bytes
    leader_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Send leader public key
    sock.sendto(
        leader_public_bytes,
        (
            LOCAL_IP,
            ECC_FOLLOWER_PORT
        )
    )

    print(
        "Leader ECC public key sent."
    )

    print(
        "Waiting for follower ECC public key..."
    )

    # Receive follower public key
    follower_public_bytes, address = (
        sock.recvfrom(1024)
    )

    print(
        "Follower ECC public key received."
    )

    # Convert bytes into ECC public key
    follower_public_key = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            follower_public_bytes
        )
    )

    # Generate shared secretonfiguration
    shared_secret = private_key.exchange(
        ec.ECDH(),
        follower_public_key
    )

    print(
        "ECC shared secret created."
    )

    # Derive AES-256 key
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


# SEND ENCRYPTED POSITION

def send_position(sock, aes, position, name):

    # Create JSON data
    data = json.dumps(
        {
            "x": position[0],
            "y": position[1],
            "z": position[2]
        }
    ).encode()

    # AES-GCM requires a unique nonce
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

    # Message = nonce + ciphertext
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

    print("Original position:")
    print(position)

    print(
        "Position encrypted using AES-GCM."
    )

    print(
        f"Encryption time: "
        f"{encryption_time:.3f} ms"
    )

    print(
        "Encrypted position sent to follower."
    )

    print("--------------------------------")


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

    print("\n================================")
    print(
        f"LEADER LEAVING {old_name}"
    )
    print(
        f"LEADER GOING TO {new_name}"
    )
    print("================================")

    # Leader starts moving away from old position FIRST

    commander.go_to(
        new_position[0],
        new_position[1],
        new_position[2],
        0,
        LEADER_MOVE_TIME,
        relative=False
    )

    # Give leader time to physically leave old position.
    #
    # This prevents follower from flying into leader.
    time.sleep(0.8)

    # Now send OLD position encrypted to follower

    send_position(
        position_sock,
        aes,
        old_position,
        old_name
    )

    # Wait until leader movement is complete
    time.sleep(
        LEADER_MOVE_TIME + 0.7
    )

    print(
        f"Leader reached {new_name}."
    )


# MAIN

def main():

    print("\n================================")
    print("STARTING LEADER")
    print("================================")

    # INITIALIZE CRAZYFLIE DRIVERS

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

    # ECC KEY EXCHANGE

    aes_key = create_aes_key(
        ecc_sock
    )

    aes = AESGCM(
        aes_key
    )

    print(
        "ECC exchange completed successfully."
    )

    # POSITION SOCKET

    position_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    # CONNECT TO LEADER DRONE

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

            print("\n================================")
            print("LEADER DRONE CONNECTED!")
            print("================================")

            # ARM

            prepare_drone(
                scf.cf,
                "Leader drone"
            )

            commander = (
                scf.cf.high_level_commander
            )

            # WAIT FOR FOLLOWER

            print("\n================================")
            print(
                "WAITING FOR FOLLOWER READY SIGNAL"
            )
            print("================================")

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
                    "\nERROR:"
                )

                print(
                    "Follower did not become ready "
                    "within 30 seconds."
                )

                return

            finally:

                ecc_sock.settimeout(None)

            # TAKEOFF

            print("\n================================")
            print("LEADER TAKING OFF")
            print("================================")

            commander.takeoff(
                FLIGHT_HEIGHT,
                TAKEOFF_TIME
            )

            time.sleep(
                TAKEOFF_TIME + 1.0
            )

            print(
                "Leader takeoff command completed."
            )

            # STEP 1:
            # LEADER GOES TO CORNER 1
            #
            # Nothing is sent yet because leader occupies
            # Corner 1.

            print("\n================================")
            print(
                "LEADER GOING TO CORNER 1"
            )
            print("================================")

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

            print(
                "Leader reached Corner 1."
            )

            # STEP 2:
            # Leader leaves Corner 1 -> Corner 2
            # Send Corner 1 to follower

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_1,
                "CORNER 1",
                CORNER_2,
                "CORNER 2"
            )

            # STEP 3:
            # Leader leaves Corner 2 -> Corner 3
            # Send Corner 2 to follower

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_2,
                "CORNER 2",
                CORNER_3,
                "CORNER 3"
            )

            # STEP 4:
            # Leader leaves Corner 3 -> Corner 4
            # Send Corner 3 to follower

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_3,
                "CORNER 3",
                CORNER_4,
                "CORNER 4"
            )

            # STEP 5:
            # Leader leaves Corner 4 -> Corner 1
            # Send Corner 4 to follower

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_4,
                "CORNER 4",
                CORNER_1,
                "CORNER 1"
            )

            # STEP 6:
            #
            # Leader has completed the entire square.
            #
            # Leader now leaves Corner 1 -> Corner 2
            #
            # Send Corner 1 to follower.
            #
            # Follower will then land at Corner 1.

            move_and_send_old_position(
                commander,
                position_sock,
                aes,
                CORNER_1,
                "CORNER 1 FINAL",
                CORNER_2,
                "CORNER 2 FINAL LANDING"
            )

            # LAND LEADER AT CORNER 2

            print("\n================================")
            print(
                "LEADER LANDING AT CORNER 2"
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
                "\nLeader landed successfully."
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