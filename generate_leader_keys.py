#-------------------------------------------------------------------------------
#This program creates a permanent private and public key pair for the Leader and 
#saves them as .pem files. These keys are later used to authenticate the Leader when 
#the drones communicate.
#-------------------------------------------------------------------------------



from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def main():

    # Generate permanent ECC signing key pair
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    # Save private key
    with open(
        "leader_signing_private_key.pem",
        "wb"
    ) as f:

        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open(
        "leader_signing_public_key.pem",
        "wb"
    ) as f:

        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("Keys generated successfully!")
    print(
        "leader_signing_private_key.pem"
    )
    print(
        "leader_signing_public_key.pem"
    )


if __name__ == "__main__":
    main()