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
