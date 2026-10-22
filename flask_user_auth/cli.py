from __future__ import annotations

import json
import secrets
import string
from typing import Any

import click
from flask import current_app
from flask.cli import AppGroup
import sqlalchemy as sa


def _coerce_column_value(model: type, field_name: str, raw_value: Any) -> Any:
    """Coerce a CLI string value to the appropriate SQLAlchemy column Python type."""
    if not isinstance(raw_value, str):
        return raw_value

    col = getattr(model, field_name, None)
    col_type = None
    try:
        col_type = getattr(col.property.columns[0], 'type', None)
    except Exception:
        table = getattr(model, '__table__', None)
        if table is not None and field_name in table.columns:
            col_type = table.columns[field_name].type

    if isinstance(col_type, sa.Boolean):
        lowered = raw_value.strip().lower()
        if lowered in ('1', 'true', 'yes', 'y', 'on'):
            return True
        if lowered in ('0', 'false', 'no', 'n', 'off'):
            return False
        raise click.BadParameter(f"Invalid boolean value {raw_value!r} for field '{field_name}'.")

    if isinstance(col_type, sa.Integer):
        try:
            return int(raw_value)
        except ValueError as exc:
            raise click.BadParameter(f"Expected integer for field '{field_name}', got {raw_value!r}.") from exc

    if isinstance(col_type, (sa.Float, sa.Numeric)):
        try:
            return float(raw_value)
        except ValueError as exc:
            raise click.BadParameter(f"Expected number for field '{field_name}', got {raw_value!r}.") from exc

    return raw_value


def _parse_extra_fields(
    model: type,
    field_items: tuple[str, ...],
    extra_args: list[str],
) -> dict[str, Any]:
    """Parse both `-f key=value` pairs and `--<column-name> <value>` extra CLI flags."""
    updates: dict[str, Any] = {}

    # 1. Parse `-f key=value` / `--field key=value`
    for item in field_items or ():
        if '=' not in item:
            raise click.BadParameter(
                f"Invalid --field value {item!r}. Expected format: KEY=VALUE (e.g. -f first_name=Ada)."
            )
        key, val = item.split('=', 1)
        key = key.strip().replace('-', '_')
        if not key:
            raise click.BadParameter(f"Empty field name in {item!r}.")
        updates[key] = _coerce_column_value(model, key, val)

    # 2. Parse arbitrary `--col-name val` or `--col-name=val` in `ctx.args`
    idx = 0
    while idx < len(extra_args):
        token = extra_args[idx]
        if token.startswith('--'):
            stripped = token[2:]
            if '=' in stripped:
                raw_key, raw_val = stripped.split('=', 1)
                idx += 1
            else:
                raw_key = stripped
                if idx + 1 < len(extra_args) and not extra_args[idx + 1].startswith('--'):
                    raw_val = extra_args[idx + 1]
                    idx += 2
                else:
                    raw_val = 'true'
                    idx += 1
            key = raw_key.strip().replace('-', '_')
            updates[key] = _coerce_column_value(model, key, raw_val)
        else:
            idx += 1

    return updates


def _validate_model_fields(model: type, fields: dict[str, Any]) -> None:
    """Ensure all target attributes exist on the user model."""
    for key in fields:
        if not hasattr(model, key):
            raise click.ClickException(
                f"Model '{model.__name__}' has no field or attribute '{key}'."
            )


def create_auth_cli(auth, name: str = 'user') -> AppGroup:
    """Create a Flask CLI ``AppGroup`` for managing users and passwords.

    Commands:
        - ``create`` / ``create-user``: Create a user (supports ``--admin``, ``-f key=val``, ``--<col> <val>``)
        - ``create-admin``: Create an administrator user (``is_admin=True``)
        - ``update``: Update a user by any lookup field (``--by email|id|phone|...``)
        - ``set-password``: Set a user's password by any lookup field
        - ``reset-password``: Reset a user's password (interactive prompt, ``--password``, or ``--generate``)
        - ``list``: List users
        - ``show``: Display serialized user JSON (``to_dict()``)
    """
    cli = AppGroup(name, help='Manage application users, admins, and passwords (flask-user-auth).')

    def _run_create(
        ctx: click.Context,
        identity: str | None,
        email_opt: str | None,
        password: str | None,
        is_admin: bool,
        is_active: bool,
        field_items: tuple[str, ...],
    ) -> None:
        model = auth.model
        identity_field = current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        extra = _parse_extra_fields(model, field_items, list(ctx.args))

        resolved_identity = (
            email_opt
            or identity
            or extra.pop(identity_field, None)
            or click.prompt(f'{identity_field.capitalize()}')
        )
        if isinstance(resolved_identity, str):
            resolved_identity = resolved_identity.strip()

        if not password:
            password = extra.pop('password', None)
        if not password:
            password = click.prompt(
                'Password', hide_input=True, confirmation_prompt=True
            )

        existing = auth.get_user_by(identity_field, resolved_identity, fallback_pk=False)
        if existing is not None:
            raise click.ClickException(
                f"User with {identity_field}={resolved_identity!r} already exists."
            )

        extra[identity_field] = resolved_identity
        if hasattr(model, 'is_admin'):
            extra['is_admin'] = bool(is_admin)
        if hasattr(model, 'is_active'):
            extra['is_active'] = bool(is_active)

        _validate_model_fields(model, extra)
        user = auth.create_user(password=password, **extra)
        role_label = 'Admin user' if getattr(user, 'is_admin', False) else 'User'
        click.secho(
            f"{role_label} created successfully ({identity_field}={resolved_identity}).",
            fg='green',
        )
        click.echo(json.dumps(auth.serialize_user(user), indent=2, default=str))

    @cli.command(
        'create',
        context_settings={'ignore_unknown_options': True, 'allow_extra_args': True},
    )
    @click.argument('identity', required=False)
    @click.option('-e', '--email', 'email_opt', help='User email / identity value.')
    @click.option('-p', '--password', help='User password (prompts if omitted).')
    @click.option('--admin/--no-admin', 'is_admin', default=False, help='Grant admin privileges.')
    @click.option('--active/--inactive', 'is_active', default=True, help='Set account active status.')
    @click.option(
        '-f',
        '--field',
        'field_items',
        multiple=True,
        metavar='KEY=VALUE',
        help='Set additional model field(s), e.g. -f first_name=Adaeze -f phone=08030001111.',
    )
    @click.pass_context
    def create_cmd(ctx, identity, email_opt, password, is_admin, is_active, field_items):
        """Create a new user (pass --admin for an administrator).

        Any extra model columns can be passed either via `-f key=value` or directly
        as `--<field-name> <value>` (e.g. `--first-name Adaeze --phone 08030001111`).
        """
        _run_create(ctx, identity, email_opt, password, is_admin, is_active, field_items)

    @cli.command(
        'create-user',
        context_settings={'ignore_unknown_options': True, 'allow_extra_args': True},
    )
    @click.argument('identity', required=False)
    @click.option('-e', '--email', 'email_opt', help='User email / identity value.')
    @click.option('-p', '--password', help='User password (prompts if omitted).')
    @click.option('--admin/--no-admin', 'is_admin', default=False, help='Grant admin privileges.')
    @click.option('--active/--inactive', 'is_active', default=True, help='Set account active status.')
    @click.option('-f', '--field', 'field_items', multiple=True, metavar='KEY=VALUE')
    @click.pass_context
    def create_user_cmd(ctx, identity, email_opt, password, is_admin, is_active, field_items):
        """Alias for `create`: create a new user account."""
        _run_create(ctx, identity, email_opt, password, is_admin, is_active, field_items)

    @cli.command(
        'create-admin',
        context_settings={'ignore_unknown_options': True, 'allow_extra_args': True},
    )
    @click.argument('identity', required=False)
    @click.option('-e', '--email', 'email_opt', help='Admin email / identity value.')
    @click.option('-p', '--password', help='Admin password (prompts if omitted).')
    @click.option('--active/--inactive', 'is_active', default=True, help='Set account active status.')
    @click.option(
        '-f',
        '--field',
        'field_items',
        multiple=True,
        metavar='KEY=VALUE',
        help='Set additional model field(s), e.g. -f first_name=Chidi -f last_name=Nwosu.',
    )
    @click.pass_context
    def create_admin_cmd(ctx, identity, email_opt, password, is_active, field_items):
        """Create a new administrator user (`is_admin=True`)."""
        _run_create(ctx, identity, email_opt, password, True, is_active, field_items)

    @cli.command(
        'update',
        context_settings={'ignore_unknown_options': True, 'allow_extra_args': True},
    )
    @click.argument('identifier')
    @click.option(
        '-b',
        '--by',
        'by_field',
        default=None,
        help='Field name to look up user by (defaults to AUTH_IDENTITY_FIELD or id).',
    )
    @click.option('--admin/--no-admin', 'is_admin', default=None, help='Toggle admin status.')
    @click.option('--active/--inactive', 'is_active', default=None, help='Toggle active status.')
    @click.option('-p', '--password', default=None, help='Optionally update password.')
    @click.option(
        '-f',
        '--field',
        'field_items',
        multiple=True,
        metavar='KEY=VALUE',
        help='Field(s) to update, e.g. -f first_name=Ngozi -f phone=08099998888.',
    )
    @click.pass_context
    def update_cmd(ctx, identifier, by_field, is_admin, is_active, password, field_items):
        """Update a user looked up by `--by <field>` (default: email or id).

        Examples:
            flask user update customer@foodmart.ng --first-name Ngozi --admin
            flask user update 2 --by id -f phone=08099998888 -f first_name=Chidi
        """
        model = auth.model
        lookup_field = by_field or current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        user = auth.get_user_by(lookup_field, identifier, fallback_pk=(by_field is None))
        if user is None:
            raise click.ClickException(
                f"User not found with {lookup_field}={identifier!r}."
            )

        updates = _parse_extra_fields(model, field_items, list(ctx.args))
        if is_admin is not None:
            updates['is_admin'] = bool(is_admin)
        if is_active is not None:
            updates['is_active'] = bool(is_active)

        if not updates and not password:
            raise click.ClickException(
                'No fields provided to update. Pass -f KEY=VALUE, --<field> <val>, --admin, --active, or -p.'
            )

        _validate_model_fields(model, updates)
        user = auth.update_user(user, password=password, **updates)
        click.secho(f"Updated user ({lookup_field}={identifier!r}) successfully.", fg='green')
        click.echo(json.dumps(auth.serialize_user(user), indent=2, default=str))

    def _run_password_change(
        identifier: str,
        by_field: str | None,
        password: str | None,
        generate: bool,
        action_label: str,
    ) -> None:
        lookup_field = by_field or current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        user = auth.get_user_by(lookup_field, identifier, fallback_pk=(by_field is None))
        if user is None:
            raise click.ClickException(
                f"User not found with {lookup_field}={identifier!r}."
            )

        generated = False
        if generate:
            alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
            password = ''.join(secrets.choice(alphabet) for _ in range(12))
            generated = True
        elif not password:
            password = click.prompt(
                'New password', hide_input=True, confirmation_prompt=True
            )

        auth.set_user_password(user, password)
        identity_display = getattr(
            user,
            current_app.config.get('AUTH_IDENTITY_FIELD', 'email'),
            identifier,
        )
        click.secho(
            f"Password {action_label} for user '{identity_display}'.",
            fg='green',
        )
        if generated:
            click.secho(f"Generated password: {password}", fg='yellow', bold=True)

    @cli.command('set-password')
    @click.argument('identifier')
    @click.option('-b', '--by', 'by_field', default=None, help='Field to look up user by (default: email or id).')
    @click.option('-p', '--password', default=None, help='New password (prompts if omitted).')
    @click.option('-g', '--generate', is_flag=True, help='Auto-generate a random password and print it.')
    def set_password_cmd(identifier, by_field, password, generate):
        """Set a user's password (looked up by email, id, or `--by <field>`)."""
        _run_password_change(identifier, by_field, password, generate, 'set')

    @cli.command('reset-password')
    @click.argument('identifier')
    @click.option('-b', '--by', 'by_field', default=None, help='Field to look up user by (default: email or id).')
    @click.option('-p', '--password', default=None, help='New password (prompts if omitted).')
    @click.option('-g', '--generate', is_flag=True, help='Auto-generate a random password and print it.')
    def reset_password_cmd(identifier, by_field, password, generate):
        """Reset a user's password (interactive prompt, `-p <password>`, or `--generate`)."""
        _run_password_change(identifier, by_field, password, generate, 'reset')

    @cli.command('show')
    @click.argument('identifier')
    @click.option('-b', '--by', 'by_field', default=None, help='Field to look up user by (default: email or id).')
    def show_cmd(identifier, by_field):
        """Display a user's serialized `to_dict()` JSON."""
        lookup_field = by_field or current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        user = auth.get_user_by(lookup_field, identifier, fallback_pk=(by_field is None))
        if user is None:
            raise click.ClickException(f"User not found with {lookup_field}={identifier!r}.")
        click.echo(json.dumps(auth.serialize_user(user), indent=2, default=str))

    @cli.command('list')
    @click.option('--admin/--no-admin', 'is_admin', default=None, help='Filter by admin status.')
    @click.option('--active/--inactive', 'is_active', default=None, help='Filter by active status.')
    def list_cmd(is_admin, is_active):
        """List users as JSON array."""
        session = auth._get_db_session()
        stmt = sa.select(auth.model)
        if is_admin is not None and hasattr(auth.model, 'is_admin'):
            stmt = stmt.where(auth.model.is_admin == bool(is_admin))
        if is_active is not None and hasattr(auth.model, 'is_active'):
            stmt = stmt.where(auth.model.is_active == bool(is_active))
        users = session.scalars(stmt).all()
        click.echo(json.dumps([auth.serialize_user(u) for u in users], indent=2, default=str))

    return cli
