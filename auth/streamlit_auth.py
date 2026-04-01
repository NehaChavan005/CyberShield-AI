import streamlit as st
from jwt import PyJWTError

from auth.security import create_access_token, decode_access_token
from auth.store import authenticate_user


def _initialize_auth_state() -> None:
    st.session_state.setdefault("auth_token", None)
    st.session_state.setdefault("current_user", None)


def login_form() -> dict | None:
    _initialize_auth_state()

    if st.session_state["auth_token"]:
        try:
            payload = decode_access_token(st.session_state["auth_token"])
            st.session_state["current_user"] = {"username": payload.get("sub")}
            return st.session_state["current_user"]
        except PyJWTError:
            st.session_state["auth_token"] = None
            st.session_state["current_user"] = None

    st.subheader("Sign in to CyberShield-AI")
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign In")

    if submitted:
        user = authenticate_user(username, password)
        if user is None:
            st.error("Invalid username or password.")
            return None

        st.session_state["auth_token"] = create_access_token(user["username"])
        st.session_state["current_user"] = user
        st.success("Login successful.")
        st.rerun()

    st.caption(
        "Demo credentials can be configured with CYBERSHIELD_DEMO_USERNAME and CYBERSHIELD_DEMO_PASSWORD."
    )
    return None


def require_login() -> dict | None:
    user = login_form()
    if user is None:
        st.stop()
    return user


def logout_button() -> None:
    if st.button("Log Out"):
        st.session_state["auth_token"] = None
        st.session_state["current_user"] = None
        st.rerun()
