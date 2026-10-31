<?php

namespace Io\Auth;

/** Why a change to users or roles was refused: the app shows its own text for each. */
enum Refusal: string
{
    case EmailTaken = 'email-taken';
    case HandleTaken = 'handle-taken';
    case NameTaken = 'name-taken';
    case InvalidHandle = 'invalid-handle';
    case InvalidName = 'invalid-name';
    case RoleTaken = 'role-taken';
    case InvalidRoleName = 'invalid-role-name';
    case UnknownRole = 'unknown-role';
    case BuiltinRole = 'builtin-role';
    case OwnAccount = 'own-account';
    case AdminOnly = 'admin-only';
    case LastAdmin = 'last-admin';
    case RoleTooStrong = 'role-too-strong';
}
