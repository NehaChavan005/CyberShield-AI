import jwt
import streamlit as st

from auth.security import create_access_token, decode_access_token
from auth.store import authenticate_user, create_user, get_user


def _initialize_auth_state() -> None:
    st.session_state.setdefault("auth_token", None)
    st.session_state.setdefault("current_user", None)
    st.session_state.setdefault("auth_page", "Sign In")


def get_authenticated_user() -> dict | None:
    _initialize_auth_state()

    if st.session_state["auth_token"]:
        try:
            payload = decode_access_token(st.session_state["auth_token"])
            username = payload.get("sub")
            user = get_user(username)
            if user:
                st.session_state["current_user"] = {
                    "username": user.get("username"),
                    "full_name": user.get("full_name"),
                }
                return st.session_state["current_user"]
        except jwt.PyJWTError:
            pass

    st.session_state["auth_token"] = None
    st.session_state["current_user"] = None
    return None


def login_form() -> dict | None:
    user = get_authenticated_user()
    if user:
        return user

    st.markdown('<div class="auth-shell">', unsafe_allow_html=True)
    st.markdown('<div class="auth-title">CyberShield-AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="auth-card">', unsafe_allow_html=True)
    st.markdown('<div class="auth-card-title">Sign In</div>', unsafe_allow_html=True)
    with st.form("login_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login", use_container_width=True)

    if submitted:
        user = authenticate_user(username, password)
        if user is None:
            st.error("Invalid username or password.")
            st.markdown("</div></div>", unsafe_allow_html=True)
            return None

        st.session_state["auth_token"] = create_access_token(user["username"])
        st.session_state["current_user"] = user
        st.success("Login successful.")
        st.rerun()

    st.markdown("</div></div>", unsafe_allow_html=True)
    return None


def signup_form() -> None:
    _initialize_auth_state()
    st.markdown('<div class="auth-shell">', unsafe_allow_html=True)
    st.markdown('<div class="auth-title">CyberShield-AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="auth-card">', unsafe_allow_html=True)
    st.markdown('<div class="auth-card-title">Sign Up</div>', unsafe_allow_html=True)
    with st.form("signup_form", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Signup", use_container_width=True)

    if submitted:
        success, message = create_user(username, username, password)
        if success:
            st.success(message)
            st.session_state["auth_page"] = "Sign In"
        else:
            st.error(message)
    st.markdown("</div></div>", unsafe_allow_html=True)


def auth_page() -> dict | None:
    user = get_authenticated_user()
    if user:
        return user

    choice = st.sidebar.radio(
        "Access",
        ["Sign In", "Sign Up"],
        index=0 if st.session_state.get("auth_page") == "Sign In" else 1,
        label_visibility="collapsed",
    )
    st.session_state["auth_page"] = choice

    if choice == "Sign In":
        return login_form()

    signup_form()
    return None


def require_login() -> dict | None:
    user = auth_page()
    if user is None:
        st.stop()
    return user


def logout_button() -> None:
    if st.button("Log Out", use_container_width=True):
        st.session_state["auth_token"] = None
        st.session_state["current_user"] = None
        st.session_state["auth_page"] = "Sign In"
        st.rerun()


def open_signup_page() -> None:
    _initialize_auth_state()
    st.session_state["auth_page"] = "Sign Up"
