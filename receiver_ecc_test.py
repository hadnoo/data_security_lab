#----------------------------------------------------------------------------
#Test the security of the ECC key exchange.
#-----------------------------------------------------------------------------
#This program receives the ECC public key and checks if it is valid. Since the 
# key was modified, the follower detects that it is invalid and rejects it. No 
# shared secret or AES key is created.
#This test does not involve any drone flight. We only test ECC security.
#-----------------------------------------------------------------------------

import socket

from cryptography.hazmat.primitives.asymmetric import ec


# CONFIGURATION

LOCAL_IP = "127.0.0.1"

ECC_LEADER_PORT = 6000
ECC_FOLLOWER_PORT = 6001


# MAIN

def main():

    print("\n================================")
    print("STARTING ECC SECURITY TEST")
    print("FOLLOWER / RECEIVER")
    print("================================")


    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (
            LOCAL_IP,
            ECC_FOLLOWER_PORT
        )
    )

    print(
        "\nWaiting for leader ECC public key..."
    )

    public_key_bytes, address = sock.recvfrom(
        1024
    )

    print(
        "\nECC public key received."
    )

    print(
        f"Received key length: "
        f"{len(public_key_bytes)} bytes"
    )

    print("\n================================")
    print("VALIDATING ECC PUBLIC KEY")
    print("================================")

    try:

        # TRY TO CONVERT RECEIVED DATA
        # INTO A VALID SECP256R1 PUBLIC KEY

        leader_public_key = (
            ec.EllipticCurvePublicKey
            .from_encoded_point(
                ec.SECP256R1(),
                public_key_bytes
            )
        )

        # IF WE REACH HERE:
        # THE KEY WAS ACCEPTED

        print(
            "\nWARNING:"
        )

        print(
            "ECC public key was accepted."
        )

        print(
            "The intended invalid-key test "
            "did NOT fail."
        )

        response = (
            b"ECC_KEY_ACCEPTED"
        )

        sock.sendto(
            response,
            (
                LOCAL_IP,
                ECC_LEADER_PORT
            )
        )

    except ValueError:

        # EXPECTED RESULT

        print("\n================================")
        print("SECURITY ALERT")
        print("================================")

        print(
            "INVALID ECC PUBLIC KEY DETECTED!"
        )

        print(
            "ECC validation FAILED."
        )

        print(
            "The received public key is not "
            "valid for SECP256R1."
        )

        print(
            "\nConnection will be rejected."
        )

        print(
            "No shared secret will be created."
        )

        print(
            "No AES key will be created."
        )

        print(
            "No drone will be armed."
        )

        print(
            "No drone will fly."
        )

        print("================================")

        response = (
            b"ECC_KEY_REJECTED"
        )

        sock.sendto(
            response,
            (
                LOCAL_IP,
                ECC_LEADER_PORT
            )
        )

    finally:

        sock.close()

    print("\n================================")
    print("FOLLOWER ECC TEST FINISHED")
    print("================================")


if __name__ == "__main__":
    main()