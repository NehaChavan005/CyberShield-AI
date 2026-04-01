from auth.config import DEMO_FULL_NAME, DEMO_PASSWORD, DEMO_USERNAME
from auth.security import hash_password, verify_password


USER_DB = {
    DEMO_USERNAME: {
        "username": DEMO_USERNAME,
        "full_name": DEMO_FULL_NAME,
        "hashed_password": hash_password(DEMO_PASSWORD),
    }
}


def authenticate_user(username: str, password: str) -> dict | None:
    user = USER_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return {"username": user["username"], "full_name": user["full_name"]}
