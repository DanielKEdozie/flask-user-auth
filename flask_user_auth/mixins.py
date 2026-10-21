from flask_login import UserMixin as FlaskLoginUserMixin
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash


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

    def to_dict(self, exclude: tuple[str, ...] = ('password_hash',)) -> dict:
        """Serialize base user attributes into a dictionary."""
        exclude_set = set(exclude or ())
        data = {
            'id': getattr(self, 'id', None),
            'email': getattr(self, 'email', None),
            'is_admin': bool(getattr(self, 'is_admin', False)),
            'is_active': bool(getattr(self, 'is_active', True)),
        }
        return {k: v for k, v in data.items() if k not in exclude_set}


# Convenient alias matching standard naming
UserMixin = AuthUserMixin
