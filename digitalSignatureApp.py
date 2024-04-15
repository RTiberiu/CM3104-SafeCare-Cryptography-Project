import streamlit as st
import os
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Author: Tiberiu Rociu, Student ID: 2006061
# CM3104 Coursework

# Password used for encrypting the private_key
encryption_password = 'A Song of Ice and Fire'

# Generate RSA private and public keys of 2048 bits 
def generate_keys():
    # Generate private key of 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
    )
    # Get public key from the private key
    public_key = private_key.public_key()
    
    return private_key, public_key

# Save the encrypted private key and the public key into separate files. 
def save_keys(private_key, public_key, private_key_name, public_key_name):
    with open(f"{private_key_name}.pem", "wb") as f:
        f.write(private_key)
    with open(f"{public_key_name}.pem", "wb") as f:
        f.write(public_key)
    
# Helper function to get the encrypted private key 
def get_encrypted_private_key(private_key):
    encrypted_private_key = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.BestAvailableEncryption(bytes(encryption_password, "UTF-8"))
        )

    return encrypted_private_key

# Helper function to get the raw public key
def get_raw_public_key(public_key):
    raw_public_key = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.PKCS1
        )
    
    return raw_public_key

# Return the private and public key from their files
def load_keys(private_key_path, public_key_path):
    with open(f"{private_key_path}.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password = encryption_password.encode('UTF-8'),
        )

    with open(f"{public_key_path}.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
        )

    return private_key, public_key

# Use the private key to sign the message and return the singature. 
# This method uses the hash function SHA256 and the padding algorithm PSS.  
def sign_message(private_key, message, timestamp):
    # Append timestamp to message
    message_with_timestamp = message + timestamp

    signature = private_key.sign(
        message_with_timestamp,
        padding.PSS( # Set the padding algorithm and salt length
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() # Set the hash function 
    )

    return signature

def get_timestamp_from_prescription():
    with open("prescription_with_timestamp.txt", "rb") as f:
        prescription = f.read()
    
    current_time = str(datetime.datetime.now()).strip()
    timestamp = prescription[-(len(current_time)):]

    return timestamp


# Validate the message using the public key and the signature, and validate that
# the timestamp is within the given expiry threshold
# Returns 2 booleans, if the signature is valid, and if the timestamp is valid 
# This method uses the hash function SHA256 and the padding algorithm PSS.  
def validate_signature(public_key, signature, message, expiry_threshold):
    signature_is_valid = False
    timestamp_is_valid = False

    # Get current time
    current_time = datetime.datetime.now()

    # Get timestamp from prescription_with_timestamp file 
    file_timestamp_bytes = get_timestamp_from_prescription()

    # Verify the signature using the public key against the message + timestamp
    try:
        public_key.verify(
            signature,
            message + file_timestamp_bytes,
            padding.PSS( # Set the padding algorithm and salt length
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # Set the hash function 
        )

        # Convert bytes to datetime object
        file_timestamp = datetime.datetime.strptime(file_timestamp_bytes.decode(), '%Y-%m-%d %H:%M:%S.%f')

        # Get the difference in seconds between now and the file timestamp
        timestamps_difference = (current_time - file_timestamp).total_seconds()

        print(f"Timestamp not older than {expiry_threshold} minute(s): {timestamps_difference < 60 * expiry_threshold} -- Difference: {timestamps_difference}")

        # Check if the timestamp is within threshold 
        if timestamps_difference < 60 * expiry_threshold:
            timestamp_is_valid = True
 
        signature_is_valid = True
    except:
        pass

    return signature_is_valid, timestamp_is_valid

def streamlit_application():
    st.title("SafeCare Prescription Digital Signature")

    option = st.selectbox(
        "Select an option", 
        ("Generate Keys", "Sign Prescription", "Verify Prescription"),
        index = None,
        placeholder = "Please select an action"
        )

    if option == "Generate Keys":
        # Generate the user keys
        private_key, public_key = generate_keys();

        # Get the encoded keys 
        encrypted_private_key = get_encrypted_private_key(private_key)
        raw_public_key = get_raw_public_key(public_key)

        # Save the keys to a file
        save_keys(encrypted_private_key, raw_public_key, "private_key", "public_key")

        # Display success message
        st.success("Key files successfully saved!")

        # Show the keys
        st.header("The user's private key")
        st.write(encrypted_private_key.decode('UTF-8'))
        st.header("The user's public key")
        st.write(raw_public_key.decode('UTF-8'))

    elif option == "Sign Prescription":
        # Validate path
        if os.path.exists("private_key.pem"):
            file_to_sign = st.file_uploader("Please upload the prescription file (.txt)", type="txt")

            # Validate that file was uploaded
            if file_to_sign is not None:
                # Get the text from the file 
                prescription_text = file_to_sign.getvalue()

                # Load the user's keys from the files 
                private_key, public_key = load_keys("private_key", "public_key")

                # Get signature and save it to a file
                timestamp_bytes = str(datetime.datetime.now()).strip().encode()
                signature = sign_message(private_key, prescription_text, timestamp_bytes)
                with open("signature.bin", "wb") as f:
                    f.write(signature)

                # Save the data + timestamp
                with open("prescription_with_timestamp.txt", "wb") as f:
                    f.write(prescription_text + timestamp_bytes)

                # Display the success and prescription message
                st.success("Prescription signed successfully.")
                st.subheader("Prescription to sign")
                st.write(prescription_text.decode())

                # Add signature value
                st.header("Signature")
                st.subheader("Byte value")
                st.write(signature)
                st.subheader("Hex value")
                st.write(signature.hex())
        else:
            st.error("Private key not found! Please generate the keys first.")

    elif option == "Verify Prescription":
        # Validate public key and singature path 
        if os.path.exists("public_key.pem") and os.path.exists("signature.bin"):
            file_to_verify = st.file_uploader("Upload the prescription file to verify. Only .txt files are allowed.", type="txt")

            # Validate that file was uploaded
            if file_to_verify is not None:
                # Get the text from the file 
                prescription_text = file_to_verify.getvalue()

                # Load the keys and signature from their files  
                private_key, public_key = load_keys("private_key", "public_key")
                with open("signature.bin", "rb") as f:
                    signature = f.read()
                
                signature_is_valid, timestamp_is_valid = validate_signature(public_key, signature, prescription_text, 1)

                # Show the status for the signature's and timestamp's validity
                st.header("Signature and timestamp status")
                if signature_is_valid:
                    st.success("Signature is valid!")
                else:
                    st.error("Signature is not valid! File was modified!")

                if timestamp_is_valid:
                    st.success("Timestamp is valid! File's life span is under 1 minute.")
                elif signature_is_valid:
                    st.error("Timestamp is not valid! File's life span is over 1 minute.")

                st.header("Final status")
                if signature_is_valid and timestamp_is_valid:
                    st.success("File is approved.")
                else:
                    st.error("File is rejected.")
        
                # Display the description
                st.header("Prescription to verify")
                st.write(prescription_text.decode())

        else:
            st.error("Public key or signature not found! Please generate the keys and sign the prescription first.")

def main():
    # Add streamlit application
    streamlit_application()


if __name__ == "__main__":
    main()

