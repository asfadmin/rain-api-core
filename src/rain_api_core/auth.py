import contextlib
import dataclasses
import hashlib
import json
import logging
from collections.abc import Mapping
from http.cookies import CookieError, SimpleCookie
from time import time
from typing import Optional
from wsgiref.handlers import format_date_time as format_7231_date

import jwt
from boto3 import client as botoclient

log = logging.getLogger(__name__)


@dataclasses.dataclass
class UserProfile:
    user_id: str
    token: str
    groups: list[str]
    first_name: str
    last_name: str
    email: str
    iat: Optional[int] = None
    exp: Optional[int] = None

    @classmethod
    def from_jwt_payload(cls, payload):
        return cls(
            user_id=payload.get("urs-user-id"),
            token=payload.get("urs-access-token"),
            groups=payload.get("urs-groups"),
            first_name=payload.get("first_name"),
            last_name=payload.get("last_name"),
            email=payload.get("email"),
            iat=payload.get("iat"),
            exp=payload.get("exp"),
        )

    def to_jwt_payload(self):
        return {
            "urs-user-id": self.user_id,
            "urs-access-token": self.token,
            "urs-groups": self.groups,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "iat": self.iat,
            "exp": self.exp,
        }


class JwtManager:
    def __init__(
        self,
        algorithm: str,
        public_key: str,
        private_key: str,
        cookie_name: str,
        blacklist={},
        session_ttl_in_hours: float = 24,
    ):
        self.algorithm = algorithm
        self.public_key = public_key
        self.private_key = private_key
        self.cookie_name = cookie_name
        self.session_ttl = int(session_ttl_in_hours * 60 * 60)
        self.black_list = blacklist

    def _get_auth_cookie(self, headers: Mapping[str, str]):
        cookie_string = (
            headers.get("cookie") or headers.get("Cookie") or headers.get("COOKIE")
        )
        if not cookie_string:
            return {}

        cookie = SimpleCookie()
        with contextlib.suppress(CookieError):
            cookie.load(cookie_string)
        return cookie.get(self.cookie_name)

    def _decode_jwt(self, token: str):
        try:
            return jwt.decode(token.encode(), self.public_key, [self.algorithm])
        except jwt.ExpiredSignatureError:
            log.info("JWT has expired")
        except jwt.InvalidSignatureError:
            log.info("JWT has failed verification")
        return None

    def _encode_jwt(self, payload: Mapping[str, str]) -> str:
        try:
            encoded = jwt.encode(payload, self.private_key, self.algorithm)
        except TypeError:
            log.error("unable to encode jwt cookie")
            return ""
        return encoded

    def _jwt_payload_from_user_profile(self, user_profile: Optional[UserProfile]):
        if user_profile is None:
            return {}
        now = int(time())
        return {
            "urs-user-id": user_profile.user_id,
            "first_name": user_profile.first_name,
            "last_name": user_profile.last_name,
            "email": user_profile.email,
            "urs-access-token": user_profile.token,
            "urs-groups": user_profile.groups,
            "iat": now,
            "exp": now + self.session_ttl,
        }

    def _in_blacklist(self, user_profile: UserProfile):
        assert user_profile.iat is not None
        user_blacklist_time = self.black_list.get(user_profile.user_id)
        if user_blacklist_time is not None:
            if user_blacklist_time >= user_profile.iat:
                return True
        return False

    def get_profile_from_headers(
        self,
        headers: Mapping[str, str],
    ) -> Optional[UserProfile]:
        """Inspects headers for auth cookie and return user_profile if authenticated, None otherwise"""
        auth_cookie = self._get_auth_cookie(headers)
        if not auth_cookie:
            return None

        jwt_decoded = self._decode_jwt(auth_cookie.value)

        if jwt_decoded is None:
            return None
        user_profile = UserProfile.from_jwt_payload(jwt_decoded)
        if self._in_blacklist(user_profile):
            return None
        return user_profile

    def get_header_to_set_auth_cookie(
        self,
        user_profile: Optional[UserProfile],
        cookie_domain: str = "",
    ):
        """Gets a header to set auth-cookie

        Parameters:
        UserProfile: UserProfile to use in construction of a cookie, if none will return header to unset/logout
        """
        payload = self._jwt_payload_from_user_profile(user_profile)
        cookie_value = self._encode_jwt(payload) if payload else "expired"
        cookie_domain = f"; Domain={cookie_domain}" if cookie_domain else ""
        if payload:
            expire_date = format_7231_date(payload["exp"])
        else:
            expire_date = "Thu, 01 Jan 1970 00:00:00 GMT"
        return {
            "SET-COOKIE": (
                f"{self.cookie_name}={cookie_value}; Expires={expire_date}; Path=/{cookie_domain}; Secure; "
                "HttpOnly; SameSite=Lax"
            )
        }


class SessionManager:
    def __init__(
        self,
        table_name: str,
        column_names: Mapping[str, str] = {
            "session_id": "SessionId",
            "iat": "CreatedAt",
            "ttl": "ExpiresAt",
        },
    ):
        self.client = botoclient("dynamodb")
        self.table_name = table_name
        self._session_id_column = column_names["session_id"]
        self._iat_column = column_names["iat"]
        self._ttl_column = column_names["ttl"]

    def revoke_session(self, user_profile: UserProfile):
        session_id = self._get_session_id(user_profile)
        exp = user_profile.exp

        assert exp is not None

        log.info(
            "Revoking session for user %s with session_id: %s",
            user_profile.user_id,
            session_id,
        )
        self.client.put_item(
            TableName=self.table_name,
            Item={
                self._session_id_column: {
                    "S": session_id,
                },
                self._iat_column: {
                    "N": str(int(time())),
                },
                self._ttl_column: {
                    "N": str(exp),
                },
            },
        )

    def is_session_revoked(self, user_profile: UserProfile) -> bool:
        session_id = self._get_session_id(user_profile)

        iat = user_profile.iat

        assert iat is not None

        log.debug(
            "Checking for revoked session for user %s with session_id: %s",
            user_profile.user_id,
            session_id,
        )
        response = self.client.query(
            TableName=self.table_name,
            KeyConditionExpression=f"{self._session_id_column} = :sessionId",
            FilterExpression=f"{self._ttl_column} > :now and {self._iat_column} >= :iat",
            ExpressionAttributeValues={
                ":sessionId": {
                    "S": session_id,
                },
                ":iat": {
                    "N": str(iat),
                },
                ":now": {
                    "N": str(int(time())),
                },
            },
        )

        is_revoked = session_id in (
            # ruff hint
            item["SessionId"]["S"]
            for item in response.get("Items", ())
        )
        if is_revoked:
            log.info("Session for user %s has been revoked", user_profile.user_id)

        return is_revoked

    def _get_session_id(self, user_profile: UserProfile) -> str:
        # Depending on how we compute the session ID here we can determine the
        # scope of the log out. If we use the entire JWT cookie payload, then
        # logging out means only invalidating that cookie. If the same user has
        # other cookies active as well then those will remain active. If instead
        # we just use the user ID, then all cookies associated with that user
        # will be invalidated.
        return hashlib.sha256(
            json.dumps(user_profile.to_jwt_payload()).encode(),
        ).hexdigest()
