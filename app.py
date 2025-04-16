# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # ----------------------------- Secure Key Setup ----------------------------- #
# # This key should be kept secret in real applications. Regenerate if restarting app.
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # ----------------------------- In-Memory Storage ----------------------------- #
# stored_data = {}  # { "encrypted_text1": {"encrypted_text": ..., "passkey": ...}, ... }
# failed_attempts = st.session_state.get("failed_attempts", 0)

# # ----------------------------- Helper Functions ----------------------------- #
# def hash_passkey(passkey):
#     """Hashes a passkey using SHA-256"""
#     return hashlib.sha256(passkey.encode()).hexdigest()

# def encrypt_data(text, passkey):
#     """Encrypts the data using Fernet"""
#     return cipher.encrypt(text.encode()).decode()

# def decrypt_data(encrypted_text, passkey):
#     """Decrypts the data if passkey matches"""
#     hashed_passkey = hash_passkey(passkey)

#     for record in stored_data.values():
#         if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed_passkey:
#             st.session_state["failed_attempts"] = 0
#             return cipher.decrypt(encrypted_text.encode()).decode()

#     st.session_state["failed_attempts"] = st.session_state.get("failed_attempts", 0) + 1
#     return None

# # ----------------------------- Streamlit UI ----------------------------- #
# st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")
# st.title("🔐 Secure Data Encryption System")

# # Sidebar navigation
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("🔍 Navigate", menu)

# # ----------------------------- Pages ----------------------------- #
# if choice == "Home":
#     st.subheader("🏠 Welcome")
#     st.write("This app lets you **securely store and retrieve sensitive data** using encrypted passkeys.")

# elif choice == "Store Data":
#     st.subheader("📂 Store New Data")
#     user_data = st.text_area("Enter data to encrypt:")
#     passkey = st.text_input("Create a secure passkey:", type="password")

#     if st.button("🔐 Encrypt & Save"):
#         if user_data and passkey:
#             hashed_passkey = hash_passkey(passkey)
#             encrypted_text = encrypt_data(user_data, passkey)
#             stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
#             st.success("✅ Data has been encrypted and stored securely!")
#             st.code(encrypted_text, language="text")
#             st.write("🔐 Stored Data:", stored_data)

#         else:
#             st.error("⚠️ Both data and passkey are required.")

# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Encrypted Data")
#     encrypted_text = st.text_area("Paste the encrypted text:")
#     passkey = st.text_input("Enter your passkey:", type="password")

#     if st.button("🔓 Decrypt"):
#         if encrypted_text and passkey:
#             decrypted_text = decrypt_data(encrypted_text, passkey)
#             attempts_left = 3 - st.session_state.get("failed_attempts", 0)

#             if decrypted_text:
#                 st.success("✅ Decrypted Data:")
#                 st.code(decrypted_text, language="text")
#             else:
#                 st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
#                 if st.session_state["failed_attempts"] >= 3:
#                     st.warning("🔒 Too many failed attempts! Redirecting to Login...")
#                     st.experimental_rerun()
#         else:
#             st.error("⚠️ Both fields are required!")

# elif choice == "Login":
#     st.subheader("🔐 Reauthorize to Continue")
#     login_pass = st.text_input("Enter master password:", type="password")
#     if st.button("Login"):
#         if login_pass == "admin123":
#             st.session_state["failed_attempts"] = 0
#             st.success("✅ Login successful! You can now retry retrieving your data.")
#             st.experimental_rerun()
#         else:
#             st.error("❌ Incorrect master password.")





import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ----------------------------- Setup ----------------------------- #
# Only generate key once and store in session
if "fernet_key" not in st.session_state:
    st.session_state["fernet_key"] = Fernet.generate_key()
cipher = Fernet(st.session_state["fernet_key"])

# Setup secure in-memory storage and attempt tracking
if "stored_data" not in st.session_state:
    st.session_state["stored_data"] = {}  # {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}

if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

# ----------------------------- Helper Functions ----------------------------- #
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for record in st.session_state["stored_data"].values():
        if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed_passkey:
            st.session_state["failed_attempts"] = 0  # Reset after success
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state["failed_attempts"] += 1
    return None

# ----------------------------- Streamlit UI ----------------------------- #
st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Sidebar navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔍 Navigate", menu)

# ----------------------------- Pages ----------------------------- #
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app lets you **securely store and retrieve sensitive data** using encrypted passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store New Data")
    user_data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Create a secure passkey:", type="password")

    if st.button("🔐 Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state["stored_data"][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data has been encrypted and stored securely!")
            st.code(encrypted_text, language="text")
            st.write("🔐 Stored Data:", st.session_state["stored_data"])
        else:
            st.error("⚠️ Both data and passkey are required.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_text = st.text_area("Paste the encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            attempts_left = 3 - st.session_state["failed_attempts"]

            if decrypted_text:
                st.success("✅ Decrypted Data:")
                st.code(decrypted_text, language="text")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state["failed_attempts"] >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

elif choice == "Login":
    st.subheader("🔐 Reauthorize to Continue")
    login_pass = st.text_input("Enter master password:", type="password")
    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state["failed_attempts"] = 0
            st.success("✅ Login successful! You can now retry retrieving your data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
