"""User and UserAuth mixins and model utilities.

Separates user profile data (User) from security credentials (UserAuth):
- User: email, is_active, is_admin, timestamps, profile data, relations.
- UserAuth: user_id (PK & FK), password_hash, last_reset_date, failed_attempts.
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash


class UserAuthMixin:
    """Mixin providing authentication credentials separated from profile."""

    @declared_attr
    def user_id(cls):
        user_table = getattr(cls, "__user_table__", "users")
        return mapped_column(
            ForeignKey(f"{user_table}.id", ondelete="CASCADE"),
            primary_key=True,
        )

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    last_reset_date: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_login_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        """Hash password and update last_reset_date to invalidate older tokens."""
        self.password_hash = generate_password_hash(password)
        self.last_reset_date = datetime.now(timezone.utc)

    def check_password(self, password: str) -> bool:
        """Verify plain-text password against stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class UserMixin:
    """Mixin providing standard user identity, timestamps, and auth relationship."""

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )

    @declared_attr
    def auth(cls):
        auth_model_name = getattr(cls, "__auth_model_name__", "UserAuth")
        return relationship(
            auth_model_name,
            backref="user",
            uselist=False,
            cascade="all, delete-orphan",
            lazy="joined",
        )

    # Password helper shortcuts:
    def set_password(self, password: str) -> None:
        """Set password on associated auth record (instantiating if needed)."""
        auth_cls = getattr(self.__class__, "auth").property.mapper.class_
        if self.auth is None:
            self.auth = auth_cls()
        self.auth.set_password(password)

    def check_password(self, password: str) -> bool:
        """Verify password against associated auth record."""
        if not self.auth:
            return False
        return self.auth.check_password(password)

    # Flask-Login compatibility interface:
    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return str(self.id)

    def to_dict(self, exclude_auth=True) -> dict:
        """Return clean dict representation of user profile."""
        data = {
            "id": self.id,
            "email": self.email,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        for col in self.__table__.columns:
            if col.name not in data and col.name != "password_hash":
                val = getattr(self, col.name, None)
                if isinstance(val, datetime):
                    val = val.isoformat()
                data[col.name] = val
        return data