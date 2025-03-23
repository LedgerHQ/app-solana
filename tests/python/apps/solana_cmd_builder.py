from typing import List
from enum import IntEnum
import base58
from nacl.signing import VerifyKey


PROGRAM_ID_SYSTEM = "11111111111111111111111111111111"

# Fake blockhash so this example doesn't need a network connection. It should be queried from the cluster in normal use.
FAKE_RECENT_BLOCKHASH = "11111111111111111111111111111111"


def verify_signature(from_public_key: bytes, message: bytes, signature: bytes):
    assert len(signature) == 64, "signature size incorrect"
    verify_key = VerifyKey(from_public_key)
    verify_key.verify(message, signature)


class SystemInstruction(IntEnum):
    CreateAccount           = 0x00
    Assign                  = 0x01
    Transfer                = 0x02
    CreateAccountWithSeed   = 0x03
    AdvanceNonceAccount     = 0x04
    WithdrawNonceAccount    = 0x05
    InitializeNonceAccount  = 0x06
    AuthorizeNonceAccount   = 0x07
    Allocate                = 0x08
    AllocateWithSeed        = 0x09
    AssignWithSeed          = 0x10
    TransferWithSeed        = 0x11
    UpgradeNonceAccount     = 0x12


class MessageHeader:
    def __init__(self, num_required_signatures: int, num_readonly_signed_accounts: int, num_readonly_unsigned_accounts: int):
        self.num_required_signatures = num_required_signatures
        self.num_readonly_signed_accounts = num_readonly_signed_accounts
        self.num_readonly_unsigned_accounts = num_readonly_unsigned_accounts

    def serialize(self) -> bytes:
        return self.num_required_signatures.to_bytes(1, byteorder='little') + \
               self.num_readonly_signed_accounts.to_bytes(1, byteorder='little') + \
               self.num_readonly_unsigned_accounts.to_bytes(1, byteorder='little')

class AccountMeta:
    pubkey: bytes
    is_signer: bool
    is_writable: bool
    def __init__(self, pubkey: bytes, is_signer: bool, is_writable: bool):
        self.pubkey = pubkey
        self.is_signer = is_signer
        self.is_writable = is_writable

# Only support Transfer instruction for now
# TODO add other instructions if the need arises
class Instruction:
    program_id: bytes
    accounts: List[AccountMeta]
    data: bytes
    from_pubkey: bytes
    to_pubkey: bytes

class SystemInstructionTransfer(Instruction):
    def __init__(self, from_pubkey: bytes, to_pubkey: bytes, amount: int):
        self.from_pubkey = from_pubkey
        self.to_pubkey = to_pubkey
        self.program_id = base58.b58decode(PROGRAM_ID_SYSTEM)
        self.accounts = [AccountMeta(from_pubkey, True, True), AccountMeta(to_pubkey, False, True)]
        self.data = (SystemInstruction.Transfer).to_bytes(4, byteorder='little') + (amount).to_bytes(8, byteorder='little')

# Cheat as we only support 1 SystemInstructionTransfer currently
# TODO add support for multiple transfers and other instructions if the needs arises
class CompiledInstruction:
    program_id_index: int
    accounts: List[int]
    data: bytes

    def __init__(self, program_id_index: int, accounts: List[int], data: bytes):
        self.program_id_index = program_id_index
        self.accounts = accounts
        self.data = data

    def serialize(self) -> bytes:
        serialized: bytes = self.program_id_index.to_bytes(1, byteorder='little')
        serialized += len(self.accounts).to_bytes(1, byteorder='little')
        for account in self.accounts:
            serialized += (account).to_bytes(1, byteorder='little')
        serialized += len(self.data).to_bytes(1, byteorder='little')
        serialized += self.data
        return serialized

# Solana communication message, header + list of public keys used by the instructions + instructions
# with references to the keys array
class Message:
    header: MessageHeader
    account_keys: List[AccountMeta]
    recent_blockhash: bytes
    compiled_instructions: List[CompiledInstruction]

    def __init__(self, instructions: List[Instruction]):
        # Cheat as we only support 1 SystemInstructionTransfer currently
        # TODO add support for multiple transfers and other instructions if the needs arises
        self.header = MessageHeader(2, 0, 1)
        self.account_keys = [instructions[0].from_pubkey, instructions[0].to_pubkey, instructions[0].program_id]
        self.recent_blockhash = base58.b58decode(FAKE_RECENT_BLOCKHASH)
        self.compiled_instructions = [CompiledInstruction(2, [0, 1], instructions[0].data)]

    def serialize(self) -> bytes:
        serialized: bytes = self.header.serialize()
        serialized += len(self.account_keys).to_bytes(1, byteorder='little')
        for account_key in self.account_keys:
            serialized += account_key
        serialized += self.recent_blockhash
        serialized += len(self.compiled_instructions).to_bytes(1, byteorder='little')
        serialized += self.compiled_instructions[0].serialize()
        return serialized

def is_printable_ascii(string: str) -> bool:
    try:
        string.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False

def is_utf8(string: str) -> bool:
    return True


PACKET_DATA_SIZE: int = 1280 - 40 - 8
U16_MAX = 2^16-1


SIGNING_DOMAIN: bytes = b"\xffsolana offchain"
# // Header Length = Signing Domain (16) + Header Version (1)
BASE_HEADER_LEN: int = len(SIGNING_DOMAIN) + 1;

# Header Length = Message Format (1) + Message Length (2)
MESSAGE_HEADER_LEN: int = 3;
# Max length of the OffchainMessage
MAX_LEN: int = U16_MAX - BASE_HEADER_LEN - MESSAGE_HEADER_LEN;
# Max Length of the OffchainMessage supported by the Ledger
MAX_LEN_LEDGER: int = PACKET_DATA_SIZE - BASE_HEADER_LEN - MESSAGE_HEADER_LEN;

class MessageFormat(IntEnum):
    RestrictedAscii = 0x00
    LimitedUtf8     = 0x01
    ExtendedUtf8    = 0x02

class v0_OffchainMessage:
    format: MessageFormat
    message: bytes
    signer_pubkey: bytes

    def __init__(self, message: bytes, signer_pubkey: bytes):
        # /// Construct a new OffchainMessage object from the given message
        if len(message) <= MAX_LEN_LEDGER:
            if is_printable_ascii(message):
                self.format = MessageFormat.RestrictedAscii
            elif is_utf8(message):
                self.format = MessageFormat.LimitedUtf8
            else:
                raise ValueError()
        elif len(message) <= MAX_LEN:
            if is_utf8(message):
                self.format = MessageFormat.ExtendedUtf8
            else:
                raise ValueError()
        else:
            raise ValueError()
        self.signer_pubkey = signer_pubkey
        self.message = message

    # Serialize the message to bytes, including the full header
    def serialize(self) -> bytes:
        # data.reserve(Self::HEADER_LEN.saturating_add(self.message.len()));
        data: bytes = b""
        # format
        data += self.format.to_bytes(1, byteorder='little')
        # signers count
        data += (1).to_bytes(1, byteorder='little')
        # signers
        data += self.signer_pubkey
        # message length
        data += len(self.message).to_bytes(2, byteorder='little')
        # message
        data += self.message
        return data


class OffchainMessage:
    version: int
    message: v0_OffchainMessage

    # Construct a new OffchainMessage object from the given version and message
    def __init__(self, version: int, message: bytes, signer_pubkey: bytes):
        self.version = version
        if version == 0:
            self.message = v0_OffchainMessage(message, signer_pubkey)
        else:
            raise ValueError()

    # Serialize the off-chain message to bytes including full header
    def serialize(self) -> bytes:
        data: bytes = b""
        # serialize signing domain
        data += SIGNING_DOMAIN
        # serialize version and call version specific serializer
        data += self.version.to_bytes(1, byteorder='little')
        # Providing EMPTY app domain
        data += bytearray(32)
        data += self.message.serialize()
        return data
