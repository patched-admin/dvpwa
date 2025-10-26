from typing import NamedTuple, Optional
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from aiopg import Connection


class User(NamedTuple):
    id: int
    first_name: str
    middle_name: Optional[str]
    last_name: str
    username: str
    pwd_hash: str
    is_admin: bool

    @classmethod
    def from_raw(cls, raw: tuple):
        return cls(*raw) if raw else None

    @staticmethod
    async def get(conn: Connection, id_: int):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE id = %s',
                (id_,),
            )
            return User.from_raw(await cur.fetchone())

    @staticmethod
    async def get_by_username(conn: Connection, username: str):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE username = %s',
                (username,),
            )
            return User.from_raw(await cur.fetchone())

    @staticmethod
    def hash_password(password: str) -> str:
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        hash = kdf.derive(password.encode('utf-8'))
        return f"{salt.hex()}${hash.hex()}"

    def check_password(self, password: str) -> bool:
        try:
            salt_str, hash_str = self.pwd_hash.split('$')
            salt = bytes.fromhex(salt_str)
            stored_hash = bytes.fromhex(hash_str)
            
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            )
            kdf.verify(password.encode('utf-8'), stored_hash)
            return True
        except:
            return False
