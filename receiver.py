#------------------------------------------------------------------------------------------
#The receiver program controls the follower drone.First, it performs an ECC/ECDH key exchange
#with the leader program. The shared secret is processed using HKDF to generate an AES-256
#session key. The follower drone is then armed and takes off. It receives encrypted position 
#data through UDP, decrypts the positions using AES-GCM, and moves to each received position. 
# Finally, it returns to Corner 1 and lands.
#------------------------------------------------------------------------------------------





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


# CONFIGURATION

FOLLOWER_URI = "radio://1/100/2M/E7E7E7E710"

LOCAL_IP = "127.0.0.1"

ECC_LEADER_PORT = 6000         #why 6000?
ECC_FOLLOWER_PORT = 6001

POSITION_PORT = 5005


# FLIGHT SETTING

FLIGHT_HEIGHT = 0.30

TAKEOFF_TIME = 2.0

FOLLOWER_MOVE_TIME = 2.5

LAND_TIME = 2.0


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

        print("High Level Commander enabled.")

    except Exception as error:

        print(
            "WARNING: Could not explicitly enable "
            "commander.enHighLevel:"
        )

        print(error)

    
    # ARM BRUSHLESS CRAZYFLIE

    print(f"Sending ARM request to {name}...")

    cf.supervisor.send_arming_request(True)

    # Give the Crazyflie time to process the request
    time.sleep(2.0)

    print(f"ARM request sent to {name}.")

    print("================================\n")


# ECC KEY EXCHANGE

def create_aes_key(sock):

    print("\n================================")
    print("ECC KEY EXCHANGE - FOLLOWER")
    print("================================")

    # Generate ECC private/public key pair
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    # Wait for leader public key
    print("Waiting for leader ECC public key...")

    leader_public_bytes, address = sock.recvfrom(1024)

    print("Leader ECC public key received.")

    # Convert received bytes into leader public key
    leader_public_key = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            leader_public_bytes
        )
    )

    # Create follower public key bytes
    follower_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Send follower public key back to leader
    sock.sendto(
        follower_public_bytes,
        (
            LOCAL_IP,
            ECC_LEADER_PORT
        )
    )

    print("Follower ECC public key sent.")

    # Create ECDH shared secret
    shared_secret = private_key.exchange(
        ec.ECDH(),
        leader_public_key
    )

    print("ECC shared secret created.")

    # Derive AES-256 session key
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


# RECEIVE AND DECRYPT POSITION

def receive_position(sock, aes):

    print("\nWaiting for encrypted position...")

    message, address = sock.recvfrom(1024)

    # First 12 bytes = AES-GCM nonce
    nonce = message[:12]

    # Remaining bytes = encrypted data
    encrypted_data = message[12:]

    decryption_start = time.perf_counter()

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
    print("ENCRYPTED POSITION RECEIVED")
    print("--------------------------------")

    print("Decrypted position:")
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


# MAIN

def main():

    print("\n================================")
    print("STARTING FOLLOWER")
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

    print("ECC exchange completed successfully.")

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

    # CONNECT TO FOLLOWER DRONE

    print("\nConnecting to follower drone...")
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
            print("FOLLOWER DRONE CONNECTED!")
            print("================================")

            # ARM

            prepare_drone(
                scf.cf,
                "Follower drone"
            )

            commander = (
                scf.cf.high_level_commander
            )

            # TAKE OFF

            print("Follower taking off...")

            commander.takeoff(
                FLIGHT_HEIGHT,
                TAKEOFF_TIME
            )

            time.sleep(
                TAKEOFF_TIME + 1.0
            )

            print(
                "Follower takeoff command completed."
            )

            # TELL LEADER FOLLOWER IS READY

            ready_sock.sendto(
                b"FOLLOWER_READY",
                (
                    LOCAL_IP,
                    ECC_LEADER_PORT
                )
            )

            print(
                "Follower is READY. "
                "Leader may start."
            )

            # FOLLOW 5 RECEIVED POSITIONS
            #
            # 1. Corner 1
            # 2. Corner 2
            # 3. Corner 3
            # 4. Corner 4
            # 5. Corner 1 again

            for i in range(5):

                print("\n================================")
                print(
                    f"WAITING FOR POSITION {i + 1}/5"
                )
                print("================================")

                x, y, z = receive_position(
                    position_sock,
                    aes
                )

                print("\nFollower flying to:")
                print(
                    f"x = {x}, "
                    f"y = {y}, "
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

                # IMPORTANT:
                # Wait until this movement is finished.
                # Do not overlap go_to commands.
                time.sleep(
                    FOLLOWER_MOVE_TIME + 0.5
                )

                print(
                    f"Follower reached "
                    f"received position {i + 1}."
                )

            # FINAL LANDING

            print("\n================================")
            print(
                "FOLLOWER FINISHED ALL POSITIONS"
            )
            print(
                "LANDING AT CORNER 1"
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
                "\nFollower landed successfully."
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