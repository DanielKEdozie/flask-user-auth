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
    """Coerce a CLI value to the appropriate SQLAlchemy column Python type."""
    if raw_value is None or not isinstance(raw_value, str):
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


def normalize_cli_extra_fields(
    cli_extra_fields: dict[str, Any] | list[str] | tuple[str, ...] | None,
) -> dict[str, dict[str, Any]]:
    """Normalize ``cli_extra_fields`` into a canonical ``{field_name: spec_dict}`` mapping.

    Supported per-field options in ``spec_dict``:
        - ``flag`` / ``flags``: ``'--first-name'`` or ``('-fn', '--first-name')``
          (defaults to ``f"--{field_name.replace('_', '-')}"``)
        - ``placeholder``: Example / placeholder text shown in ``--help`` metavar and interactive prompts
        - ``prompt``: ``bool`` or ``str`` prompt label used during ``create`` / ``create-admin``
          when the option is not passed on the command line
        - ``default``: Default value when omitted on ``create``
        - ``required``: Whether a non-empty value is required on ``create`` (default ``False``)
        - ``help``: Custom option help text for ``--help``
        - ``type``: Click/Python type converter (auto-coerced from SQLAlchemy column if omitted)
        - ``hide_input``: Hide input when prompting interactively (default ``False``)
    """
    if not cli_extra_fields:
        return {}

    raw_map: dict[str, Any]
    if isinstance(cli_extra_fields, (list, tuple, set)):
        raw_map = {str(name): {} for name in cli_extra_fields if name}
    elif isinstance(cli_extra_fields, dict):
        raw_map = dict(cli_extra_fields)
    else:
        return {}

    normalized: dict[str, dict[str, Any]] = {}
    for field_name, raw_spec in raw_map.items():
        if not field_name or not isinstance(field_name, str):
            continue
        clean_name = field_name.strip()
        if isinstance(raw_spec, str):
            spec: dict[str, Any] = {'flag': raw_spec}
        elif isinstance(raw_spec, dict):
            spec = dict(raw_spec)
        else:
            spec = {}

        default_flag = f"--{clean_name.replace('_', '-')}"
        raw_flag = spec.get('flag') or spec.get('flags') or default_flag
        if isinstance(raw_flag, str):
            flags = (raw_flag.strip(),)
        elif isinstance(raw_flag, (list, tuple)):
            flags = tuple(str(f).strip() for f in raw_flag if f)
        else:
            flags = (default_flag,)

        label = clean_name.replace('_', ' ').capitalize()
        placeholder = spec.get('placeholder')
        prompt_cfg = spec.get('prompt', False)
        if prompt_cfg is True:
            prompt_text: str | None = label
        elif isinstance(prompt_cfg, str) and prompt_cfg.strip():
            prompt_text = prompt_cfg.strip()
        else:
            prompt_text = None

        help_text = spec.get('help') or (
            f"{label} (e.g. {placeholder})." if placeholder else f"{label}."
        )

        normalized[clean_name] = {
            'field_name': clean_name,
            'flags': flags,
            'placeholder': str(placeholder) if placeholder is not None else None,
            'prompt': prompt_text,
            'default': spec.get('default'),
            'required': bool(spec.get('required', False)),
            'help': help_text,
            'type': spec.get('type'),
            'hide_input': bool(spec.get('hide_input', False)),
        }

    return normalized


def _attach_extra_field_options(
    extra_specs: dict[str, dict[str, Any]],
):
    """Decorator that attaches Click options for each configured ``cli_extra_fields`` entry."""
    def decorator(fn):
        for field_name, spec in reversed(list(extra_specs.items())):
            param_decls = (*spec['flags'], f"extra__{field_name}")
            option_kwargs: dict[str, Any] = {
                'default': None,
                'help': spec['help'],
            }
            if spec['placeholder']:
                option_kwargs['metavar'] = spec['placeholder']
            if spec['type'] is not None:
                option_kwargs['type'] = spec['type']
            fn = click.option(*param_decls, **option_kwargs)(fn)
        return fn

    return decorator


def _collect_extra_field_values(
    model: type,
    extra_specs: dict[str, dict[str, Any]],
    kwargs: dict[str, Any],
    *,
    is_create: bool,
) -> dict[str, Any]:
    """Extract and coerce ``cli_extra_fields`` values from Click kwargs (prompting on create if configured)."""
    values: dict[str, Any] = {}
    for field_name, spec in extra_specs.items():
        raw_val = kwargs.pop(f"extra__{field_name}", None)

        if raw_val is None and is_create and spec['prompt']:
            prompt_label = spec['prompt']
            if spec['placeholder']:
                prompt_label = f"{prompt_label} [{spec['placeholder']}]"
            default_for_prompt = (
                spec['default']
                if spec['default'] is not None
                else ('' if not spec['required'] else None)
            )
            prompted = click.prompt(
                prompt_label,
                default=default_for_prompt,
                show_default=spec['default'] is not None,
                hide_input=spec['hide_input'],
            )
            if prompted != '' or spec['default'] is not None:
                raw_val = prompted

        if raw_val is None and is_create and spec['default'] is not None:
            raw_val = spec['default']

        if raw_val is None and is_create and spec['required']:
            flag_display = '/'.join(spec['flags'])
            raise click.ClickException(
                f"Missing required field '{field_name}' (pass {flag_display})."
            )

        if raw_val is not None:
            values[field_name] = _coerce_column_value(model, field_name, raw_val)

    return values


def _validate_model_fields(model: type, fields: dict[str, Any]) -> None:
    """Ensure all target attributes exist on the user model."""
    for key in fields:
        if not hasattr(model, key):
            raise click.ClickException(
                f"Model '{model.__name__}' has no field or attribute '{key}'."
            )


def create_auth_cli(
    auth,
    name: str = 'user',
    cli_extra_fields: dict[str, Any] | list[str] | tuple[str, ...] | None = None,
) -> AppGroup:
    """Create a Flask CLI ``AppGroup`` for managing users and passwords.

    Commands:
        - ``create`` / ``create-user``: Create a user (supports ``--admin`` and ``cli_extra_fields``)
        - ``create-admin``: Create an administrator user (``is_admin=True``)
        - ``update``: Update a user by any lookup field (``--by email|id|...``)
        - ``set-password``: Set a user's password by any lookup field
        - ``reset-password``: Reset a user's password (interactive prompt, ``--password``, or ``--generate``)
        - ``list``: List users
        - ``show``: Display serialized user JSON (``to_dict()``)
    """
    extra_specs = normalize_cli_extra_fields(
        cli_extra_fields if cli_extra_fields is not None else getattr(auth, 'cli_extra_fields', None)
    )
    cli = AppGroup(name, help='Manage application users, admins, and passwords (flask-user-auth).')

    def _run_create(
        identity: str | None,
        email_opt: str | None,
        password: str | None,
        is_admin: bool,
        is_active: bool,
        extra_kwargs: dict[str, Any],
    ) -> None:
        model = auth.model
        identity_field = current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        extra = _collect_extra_field_values(
            model, extra_specs, extra_kwargs, is_create=True
        )

        resolved_identity = (
            email_opt
            or identity
            or extra.pop(identity_field, None)
            or click.prompt(f'{identity_field.capitalize()}')
        )
        if isinstance(resolved_identity, str):
            resolved_identity = resolved_identity.strip()

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

    @cli.command('create')
    @click.argument('identity', required=False)
    @click.option('-e', '--email', 'email_opt', help='User email / identity value.')
    @click.option('-p', '--password', help='User password (prompts if omitted).')
    @click.option('--admin/--no-admin', 'is_admin', default=False, help='Grant admin privileges.')
    @click.option('--active/--inactive', 'is_active', default=True, help='Set account active status.')
    @_attach_extra_field_options(extra_specs)
    def create_cmd(identity, email_opt, password, is_admin, is_active, **extra_kwargs):
        """Create a new user (pass --admin for an administrator)."""
        _run_create(identity, email_opt, password, is_admin, is_active, extra_kwargs)

    @cli.command('create-user')
    @click.argument('identity', required=False)
    @click.option('-e', '--email', 'email_opt', help='User email / identity value.')
    @click.option('-p', '--password', help='User password (prompts if omitted).')
    @click.option('--admin/--no-admin', 'is_admin', default=False, help='Grant admin privileges.')
    @click.option('--active/--inactive', 'is_active', default=True, help='Set account active status.')
    @_attach_extra_field_options(extra_specs)
    def create_user_cmd(identity, email_opt, password, is_admin, is_active, **extra_kwargs):
        """Alias for `create`: create a new user account."""
        _run_create(identity, email_opt, password, is_admin, is_active, extra_kwargs)

    @cli.command('create-admin')
    @click.argument('identity', required=False)
    @click.option('-e', '--email', 'email_opt', help='Admin email / identity value.')
    @click.option('-p', '--password', help='Admin password (prompts if omitted).')
    @click.option('--active/--inactive', 'is_active', default=True, help='Set account active status.')
    @_attach_extra_field_options(extra_specs)
    def create_admin_cmd(identity, email_opt, password, is_active, **extra_kwargs):
        """Create a new administrator user (`is_admin=True`)."""
        _run_create(identity, email_opt, password, True, is_active, extra_kwargs)

    @cli.command('update')
    @click.argument('identifier')
    @click.option(
        '-b',
        '--by',
        'by_field',
        default=None,
        help='Field name to look up user by (defaults to AUTH_IDENTITY_FIELD or id).',
    )
    @click.option('-e', '--email', 'email_val', default=None, help='Update user email.')
    @click.option('--admin/--no-admin', 'is_admin', default=None, help='Toggle admin status.')
    @click.option('--active/--inactive', 'is_active', default=None, help='Toggle active status.')
    @click.option('-p', '--password', default=None, help='Optionally update password.')
    @_attach_extra_field_options(extra_specs)
    def update_cmd(identifier, by_field, email_val, is_admin, is_active, password, **extra_kwargs):
        """Update a user looked up by `--by <field>` (default: email or id)."""
        model = auth.model
        identity_field = current_app.config.get('AUTH_IDENTITY_FIELD', 'email')
        lookup_field = by_field or identity_field
        user = auth.get_user_by(lookup_field, identifier, fallback_pk=(by_field is None))
        if user is None:
            raise click.ClickException(
                f"User not found with {lookup_field}={identifier!r}."
            )

        updates = _collect_extra_field_values(
            model, extra_specs, extra_kwargs, is_create=False
        )
        if email_val is not None:
            updates[identity_field] = email_val.strip()
        if is_admin is not None:
            updates['is_admin'] = bool(is_admin)
        if is_active is not None:
            updates['is_active'] = bool(is_active)

        if not updates and not password:
            configured_flags = ', '.join(
                spec['flags'][-1] for spec in extra_specs.values()
            )
            hint = f", {configured_flags}" if configured_flags else ''
            raise click.ClickException(
                f"No fields provided to update. Pass --email, --admin, --active, -p{hint}."
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
