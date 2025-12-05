########################################################################
# COMPONENT:
#    CONTROL
# Author:
#    Br. Helfrich, Kyle Mueller, Lincoln Allen
# Summary:
#    This module stores the Bell-LaPadula policy data structures
#    and implements the corresponding access-control checks.
########################################################################

from enum import IntEnum

# SECURITY LEVEL
class SecurityLevel(IntEnum):
    PUBLIC       = 0
    CONFIDENTIAL = 1
    PRIVILEGED   = 2
    SECRET       = 3


# Mapping between the textual labels and SecurityLevel values.
_label_to_level = {
    "Public"      : SecurityLevel.PUBLIC,
    "Confidential": SecurityLevel.CONFIDENTIAL,
    "Privileged"  : SecurityLevel.PRIVILEGED,
    "Secret"      : SecurityLevel.SECRET,
}


def _normalize_label(label):
    return str(label).strip().capitalize()


def level_from_label(label):
    # Convert a textual label into a SecurityLevel (default: PUBLIC).
    return _label_to_level.get(_normalize_label(label), SecurityLevel.PUBLIC)


def label_from_level(level):
    # Convert a SecurityLevel back to its canonical label.
    for name, value in _label_to_level.items():
        if value == level:
            return name
    return "Public"


# SUBJECT (USER) CLEARANCES
_user_clearance = {
    "AdmiralAbe"    : SecurityLevel.SECRET,
    "CaptainCharlie": SecurityLevel.PRIVILEGED,
    "SeamanSam"     : SecurityLevel.CONFIDENTIAL,
    "SeamanSue"     : SecurityLevel.CONFIDENTIAL,
    "SeamanSly"     : SecurityLevel.CONFIDENTIAL,
}

_default_clearance = SecurityLevel.PUBLIC


def clearance_for_user(username):
    # Look up the clearance for a user. Users not explicitly listed in the policy are treated as PUBLIC.
    return _user_clearance.get(username, _default_clearance)


# OBJECT (MESSAGE) CLASSIFICATIONS

# message-id -> SecurityLevel
_message_level = {}

# Current session user
_current_user = None


def set_current_user(username):
    # Record the identity of the current subject (logged-in user).
    global _current_user
    _current_user = username


def get_current_user():
    # Return the name of the current subject, if one is set.
    return _current_user


def register_message(message_id, label=None, author=None):
    """
    Register the classification of a message.
      * If 'label' is provided, use that classification.
      * Else if 'author' is provided, classify at the author's clearance.
      * Else default to PUBLIC.
    """
    if label is not None:
        level = level_from_label(label)
    elif author is not None:
        level = clearance_for_user(author)
    else:
        level = SecurityLevel.PUBLIC

    _message_level[message_id] = level


def _resolve_user(username):
    """
    Resolve the subject whose access is being checked. If no explicit
    subject is supplied, fall back to the current session user. If
    still unknown, use the empty string, which is treated as PUBLIC.
    """
    if username is not None:
        return username
    if _current_user is not None:
        return _current_user
    return ""


# BELL-LAPADULA ACCESS-CONTROL CHECKS
def can_read_message(message_id, username=None):
    """
    Simple security property ("no read up"):
        A subject S may read an object O only if
            Level(Subject) >= Level(Object)
    """
    user = _resolve_user(username)
    subject_level = clearance_for_user(user)
    object_level = _message_level.get(message_id, SecurityLevel.PUBLIC)
    return subject_level >= object_level


def can_write_message(message_id, username=None):
    """
    *-property ("no write down"):
        A subject may write to an object only if
            Level(Subject) <= Level(Object)
    """
    user = _resolve_user(username)
    subject_level = clearance_for_user(user)
    object_level = _message_level.get(message_id, SecurityLevel.PUBLIC)
    return subject_level <= object_level
