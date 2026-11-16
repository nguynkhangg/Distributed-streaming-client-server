"""CCP exception types and coarse network-error classification."""
from __future__ import annotations

import errno
from enum import Enum

class CCPException(Exception):
    pass


class PacketError(CCPException):
    pass


class MalformedPacketError(PacketError):
    pass


class UnknownPacketTypeError(PacketError):
    pass


class AuthenticationError(CCPException):
    pass


class SessionError(CCPException):
    pass


class FileTransferError(CCPException):
    pass


class EncryptionError(CCPException):
    pass


class HandshakeTimeoutError(CCPException, TimeoutError):
    pass


class NetworkErrorClass(str, Enum):
    TIMEOUT = "timeout"
    RESET = "reset"
    UNREACHABLE = "unreachable"
    CLOSED = "closed"
    OTHER = "other"


def classify_network_error(exc: BaseException) -> NetworkErrorClass:
    """Map OSError / socket errors into a coarse class for UI / logging."""
    if isinstance(exc, TimeoutError):
        return NetworkErrorClass.TIMEOUT
    if isinstance(exc, ConnectionResetError):
        return NetworkErrorClass.RESET
    if isinstance(exc, BrokenPipeError):
        return NetworkErrorClass.CLOSED
    if isinstance(exc, ConnectionRefusedError):
        return NetworkErrorClass.UNREACHABLE
    if isinstance(exc, OSError):
        en = getattr(exc, "errno", None)
        if en in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
            return NetworkErrorClass.TIMEOUT
        if en in (errno.ECONNRESET, errno.ECONNABORTED):
            return NetworkErrorClass.RESET
        if en in (errno.EPIPE, errno.ENOTCONN):
            return NetworkErrorClass.CLOSED
        if en in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ECONNREFUSED):
            return NetworkErrorClass.UNREACHABLE
    return NetworkErrorClass.OTHER
