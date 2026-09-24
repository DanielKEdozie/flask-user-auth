"""Click CLI commands for user management."""
from typing import Any
import click
from flask.cli import AppGroup


def create_user_cli(extension: Any, group_name: str = "user") -> AppGroup:
    """Create Click CLI group for user administration."""
    user_cli = AppGroup(group_name, help="User and authentication management commands.")

    @user_cli.command("list")
    @click.option("--limit", default=50, help="Maximum number of users to show.")
    @click.option("--role", default=None, help="Filter by role.")
    @click.option("--active/--all", default=False, help="Show only active users.")
    def list_users(limit, role, active):
        """List registered users."""
        session = extension.session
        model = extension.user_model
        from sqlalchemy import select
        stmt = select(model)
        if active:
            stmt = stmt.where(model.is_active == True)
        if role and hasattr(model, "role"):
            stmt = stmt.where(getattr(model, "role") == role)
        stmt = stmt.limit(limit)
        users = session.execute(stmt).scalars().all()

        if not users:
            click.echo("No users found.")
            return

        click.echo("-" * 75)
        click.echo(f"{'ID':<6} {'Email':<30} {'Role/Admin':<15} {'Active':<8} {'Created'}")
        click.echo("-" * 75)
        for u in users:
            role_str = getattr(u, "role", "admin" if u.is_admin else "user")
            created_str = u.created_at.strftime("%Y-%m-%d") if u.created_at else "-"
            click.echo(
                f"{u.id:<6} {u.email:<30} {role_str:<15} {str(u.is_active):<8} {created_str}"
            )
        click.echo("-" * 75)
        click.echo(f"Total: {len(users)} user(s)")

    @user_cli.command("create")
    @click.option("--email", prompt=True, help="User email address.")
    @click.password_option("--password", prompt=True, help="User password.")
    @click.option("--name", default=None, help="User full name.")
    @click.option("--admin", is_flag=True, default=False, help="Grant administrator privileges.")
    def create_user(email, password, name, admin):
        """Create a new user account."""
        email = email.strip().lower()
        if extension.find_user_by_email(email):
            click.secho(f"Error: User with email '{email}' already exists.", fg="red")
            return

        kwargs = {"email": email, "is_admin": admin}
        if name and hasattr(extension.user_model, "name"):
            kwargs["name"] = name
        if hasattr(extension.user_model, "role"):
            kwargs["role"] = "admin" if admin else "user"

        user = extension.user_model(**kwargs)
        user.set_password(password)

        session = extension.session
        session.add(user)
        session.commit()

        tag = "Administrator" if admin else "User"
        click.secho(f"Success: {tag} '{email}' created with ID #{user.id}.", fg="green")

    @user_cli.command("create-admin")
    @click.option("--email", prompt=True, help="Admin email address.")
    @click.password_option("--password", prompt=True, help="Admin password.")
    @click.option("--name", default=None, help="Admin full name.")
    def create_admin(email, password, name):
        """Shortcut to create an administrator account."""
        create_user.callback(email=email, password=password, name=name, admin=True)

    @user_cli.command("set-password")
    @click.option("--email", prompt=True, help="User email address.")
    @click.password_option("--password", prompt=True, help="New password.")
    def set_password(email, password):
        """Reset a user's password (revoking active tokens)."""
        email = email.strip().lower()
        user = extension.find_user_by_email(email)
        if not user:
            click.secho(f"Error: User '{email}' not found.", fg="red")
            return

        user.set_password(password)
        extension.session.commit()
        click.secho(f"Success: Password for '{email}' has been reset.", fg="green")

    @user_cli.command("activate")
    @click.option("--email", prompt=True, help="User email address.")
    def activate(email):
        """Activate a user account."""
        email = email.strip().lower()
        user = extension.find_user_by_email(email)
        if not user:
            click.secho(f"Error: User '{email}' not found.", fg="red")
            return

        user.is_active = True
        extension.session.commit()
        click.secho(f"Success: User '{email}' activated.", fg="green")

    @user_cli.command("deactivate")
    @click.option("--email", prompt=True, help="User email address.")
    def deactivate(email):
        """Deactivate a user account."""
        email = email.strip().lower()
        user = extension.find_user_by_email(email)
        if not user:
            click.secho(f"Error: User '{email}' not found.", fg="red")
            return

        user.is_active = False
        extension.session.commit()
        click.secho(f"Success: User '{email}' deactivated.", fg="yellow")

    @user_cli.command("delete")
    @click.option("--email", prompt=True, help="User email address.")
    @click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
    def delete(email, yes):
        """Permanently delete a user account and credentials."""
        email = email.strip().lower()
        user = extension.find_user_by_email(email)
        if not user:
            click.secho(f"Error: User '{email}' not found.", fg="red")
            return

        if not yes:
            click.confirm(f"Are you sure you want to delete '{email}'?", abort=True)

        session = extension.session
        session.delete(user)
        session.commit()
        click.secho(f"Success: User '{email}' deleted.", fg="green")

    return user_cli