from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum

from flask_login import UserMixin as FlaskLoginUserMixin
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash


def _serialize_value(value):
    """Convert non-JSON-native Python values into serializable primitives."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, Enum):
        return value.value
    return value


class AuthUserMixin(FlaskLoginUserMixin):
    """SQLAlchemy 2.0+ declarative user mixin providing core auth fields and helpers.

    Includes:
        - ``id``: ``Mapped[int]`` primary key
        - ``email``: ``Mapped[str]`` unique, indexed email
        - ``password_hash``: ``Mapped[str]`` hashed password string
        - ``is_admin``: ``Mapped[bool]`` flag (default ``False``)
        - ``is_active``: ``Mapped[bool]`` flag (default ``True``), overriding
          ``flask_login.UserMixin.is_active`` with a persistent mapped column
    """

    __serialize_exclude__: tuple[str, ...] = ('password_hash', 'password')
    __serialize_properties__: tuple[str, ...] = ('full_name',)

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    email: Mapped[str] = mapped_column(
        sa.String(255), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(
        sa.Boolean,
        default=False,
        nullable=False,
        server_default=sa.false(),
    )
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean,
        default=True,
        nullable=False,
        server_default=sa.true(),
    )

    @property
    def password(self) -> str:
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, raw_password: str) -> None:
        self.set_password(raw_password)

    def set_password(self, raw_password: str) -> None:
        """Hash and store ``raw_password`` on ``password_hash``."""
        if not raw_password:
            raise ValueError('Password cannot be empty')
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Verify ``raw_password`` against ``password_hash``."""
        if not self.password_hash or not raw_password:
            return False
        return check_password_hash(self.password_hash, raw_password)

    def get_id(self) -> str | None:
        """Return the primary key as a string for Flask-Login."""
        pk_attr = getattr(self, '__auth_pk_field__', 'id')
        value = getattr(self, pk_attr, None)
        return str(value) if value is not None else None

    def to_dict(
        self,
        exclude: tuple[str, ...] | list[str] | set[str] | None = None,
        include: tuple[str, ...] | list[str] | set[str] | None = None,
    ) -> dict:
        """Serialize all mapped model columns (and configured properties) into a dict.

        Automatically excludes ``password_hash`` and ``password`` by default,
        plus any field names listed in ``__serialize_exclude__`` or ``exclude``.
        """
        default_exclude = set(getattr(self, '__serialize_exclude__', ('password_hash', 'password')))
        default_exclude.update({'password_hash', 'password'})
        if exclude:
            default_exclude.update(exclude)

        include_only = set(include) if include is not None else None
        data: dict = {}

        # 1. Inspect mapped SQLAlchemy column attributes dynamically
        try:
            mapper = sa.inspect(self.__class__)
            col_keys = [attr.key for attr in mapper.column_attrs]
        except Exception:
            table = getattr(self, '__table__', None)
            if table is not None:
                col_keys = [col.name for col in table.columns]
            else:
                col_keys = ['id', 'email', 'is_admin', 'is_active']

        for key in col_keys:
            if key in default_exclude:
                continue
            if include_only is not None and key not in include_only:
                continue
            val = getattr(self, key, None)
            if key in ('is_admin', 'is_active') and val is not None:
                val = bool(val)
            data[key] = _serialize_value(val)

        # 2. Include safe computed properties (e.g. `full_name` or `__serialize_properties__`)
        prop_keys = list(getattr(self, '__serialize_properties__', ('full_name',)) or ())
        if include_only is not None:
            for extra_key in include_only:
                if extra_key not in data and extra_key not in prop_keys:
                    prop_keys.append(extra_key)

        for prop in prop_keys:
            if prop in default_exclude or prop in data:
                continue
            if include_only is not None and prop not in include_only:
                continue
            if hasattr(self.__class__, prop):
                try:
                    data[prop] = _serialize_value(getattr(self, prop))
                except Exception:
                    pass

        return data

    def to_auth_dict(self, **kwargs) -> dict:
        """Alias for :meth:`to_dict`."""
        return self.to_dict(**kwargs)


# Convenient alias matching standard naming
UserMixin = AuthUserMixin
