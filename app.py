
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64

# ----------------------------- App Config ----------------------------- #
st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")

# ----------------------------- Session Setup ----------------------------- #
if "fernet_key" not in st.session_state:
    st.session_state["fernet_key"] = Fernet.generate_key()
cipher = Fernet(st.session_state["fernet_key"])

if "stored_data" not in st.session_state:
    st.session_state["stored_data"] = {}

if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0


if "choice" not in st.session_state:
    st.session_state["choice"] = "Home"

# ----------------------------- Helper Functions ----------------------------- #
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for record in st.session_state["stored_data"].values():
        if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed_passkey:
            st.session_state["failed_attempts"] = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state["failed_attempts"] += 1
    return None

def download_link(data, filename):
    b64 = base64.b64encode(data.encode()).decode()
    return f'<a href="data:file/txt;base64,{b64}" download="{filename}">📥 Download TXT File</a>'


# ----------------------------- Theme Toggle ----------------------------- #
st.markdown(
    """
    <style>
    .dark-mode { background-color: #1e1e1e; color: white; }
    .light-mode { background-color: #f8f9fa; color: black; }
    </style>
    """,
    unsafe_allow_html=True
)



# ----------------------------- Sidebar Navigation (with sync fix) ----------------------------- #
menu = ["Home", "Store Data", "Retrieve Data", "Login"]

selected = st.sidebar.selectbox("🔍 Navigate", menu, index=menu.index(st.session_state["choice"]))
if selected != st.session_state["choice"]:
    st.session_state["choice"] = selected
    st.experimental_rerun()

choice = st.session_state["choice"]



# ----------------------------- Pages ----------------------------- #
if choice == "Home":
    st.subheader("🏠 Welcome to Secure Data Vault")
    st.write("This app allows you to securely **encrypt and store sensitive information** using a custom passkey.")
    st.info("🔐 AES-based encryption with Fernet + password hashing.")

elif choice == "Store Data":
    st.subheader("📦 Store Encrypted Data")
    user_data = st.text_area("🔸 Enter Data")
    passkey = st.text_input("🔑 Create Passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state["stored_data"][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text)
        else:
            st.warning("⚠️ Please fill both fields.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Decrypt Stored Data")
    encrypted_text = st.text_area("📥 Paste Encrypted Text")
    passkey = st.text_input("🔑 Enter Passkey", type="password")

    if st.button("🔓 Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            attempts_left = 3 - st.session_state["failed_attempts"]

            if decrypted_text:
                st.success("✅ Decrypted Data:")
                st.code(decrypted_text)

                st.markdown(download_link(decrypted_text, "decrypted_data.txt"), unsafe_allow_html=True)

                
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state["failed_attempts"] >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                    st.session_state["choice"] = "Login"
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Fill both fields to proceed.")

elif choice == "Login":
    st.subheader("🔐 Re-Authorization")
    
    if st.session_state["failed_attempts"] >= 3:
        st.info("⚠️ Too many failed attempts! Please reauthorize.")

    login_pass = st.text_input("🔑 Master Password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state["failed_attempts"] = 0
            st.success("✅ Login successful! You can now retry retrieving your data.")
            st.session_state["choice"] = "Retrieve Data"
            st.experimental_rerun()
        else:
            st.error("❌ Wrong master password!")

# ----------------------------- Close Theme Wrapper ----------------------------- #
st.markdown("</div>", unsafe_allow_html=True)
