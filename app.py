import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher = Fernet(st.session_state.fernet_key)

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation handling
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
if st.session_state.failed_attempts >= 3:
    st.sidebar.error("🔒 Account locked - Requires reauthorization!")
    choice = "Login"
else:
    choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.markdown("""
    ### Features:
    - **Secure Storage**: Encrypt data with military-grade encryption
    - **Passkey Protection**: Access data only with correct passkey
    - **Account Lock**: 3 failed attempts trigger account lock
    - **In-Memory Security**: No databases used
    """)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    identifier = st.text_input("Unique Data Name (e.g., 'my_secret_notes')")
    user_data = st.text_area("Data to Encrypt", height=150)
    passkey = st.text_input("Create Passkey", type="password")

    if st.button("🔒 Encrypt & Save"):
        if identifier and user_data and passkey:
            if identifier in st.session_state.stored_data:
                st.error("⚠️ This name already exists! Use a unique name")
            else:
                encrypted_text = encrypt_data(user_data)
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[identifier] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data encrypted and stored successfully!")
                st.balloons()
        else:
            st.error("❌ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    identifier = st.text_input("Enter Data Name")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("🔓 Decrypt"):
        if identifier and passkey:
            if identifier not in st.session_state.stored_data:
                st.error("❌ Data name not found!")
            else:
                data_entry = st.session_state.stored_data[identifier]
                if hash_passkey(passkey) == data_entry["passkey"]:
                    decrypted_text = decrypt_data(data_entry["encrypted_text"])
                    st.session_state.failed_attempts = 0
                    st.success("Decrypted Successfully!")
                    st.text_area("Decrypted Content", decrypted_text, height=200)
                else:
                    st.session_state.failed_attempts += 1
                    remaining = 3 - st.session_state.failed_attempts
                    error_msg = f"❌ Invalid passkey! {remaining} attempts remaining" if remaining > 0 else "🚨 Account locked! Contact administrator"
                    st.error(error_msg)
                    
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.failed_attempts = 3
                        st.rerun()
        else:
            st.error("❌ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Administrator Reauthorization")
    login_pass = st.text_input("Enter Master Password", type="password")
    
    if st.button("🛡️ Authenticate"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Authentication Successful!")
            st.rerun()
        else:
            st.error("❌ Invalid administrator password")

# Security enhancements
st.markdown("---")
st.markdown("### Security Features:")
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("🔐 **Fernet Encryption**\nAES-128-CBC")
with col2:
    st.markdown("🔒 **SHA-256 Hashing**\nSecure passkey storage")
with col3:
    st.markdown("🚨 **Account Lock**\n3 failed attempts")

# Hide Streamlit default features
hide_st_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
"""
st.markdown(hide_st_style, unsafe_allow_html=True)