from typing import List, Generator, Optional
from enum import IntEnum
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.error import ExceptionRAPDU
from ragger.pki import SigningPartner

from .tlv import format_tlv
from .solana_keychain import Key, sign_data
from .solana_signing_partners import (
    TRUSTED_NAME_PARTNER,
    DYNAMIC_TOKEN_PARTNER,
    INSTRUCTION_DESCRIPTOR_PARTNER,
    TRANSACTION_CHECK_PARTNER,
)

from solders.hash import Hash
from solders.message import Message
from solders.transaction import Transaction

class INS(IntEnum):
    # DEPRECATED - Use non "16" suffixed variants below
    INS_GET_APP_CONFIGURATION16 = 0x01
    INS_GET_PUBKEY16 = 0x02
    INS_SIGN_MESSAGE16 = 0x03
    # END DEPRECATED
    INS_GET_APP_CONFIGURATION = 0x04
    INS_GET_PUBKEY = 0x05
    INS_SIGN_MESSAGE = 0x06
    INS_SIGN_OFFCHAIN_MESSAGE = 0x07
    INS_SIGN_MESSAGE_PREVIEW = 0x08
    INS_SIGN_MESSAGE_DELAYED = 0x09
    INS_INSTRUCTION_DESCRIPTOR = 0x16
    INS_GET_CHALLENGE = 0x20
    INS_TRUSTED_INFO = 0x21
    INS_DYNAMIC_TOKEN = 0x22
    INS_TRANSACTION_CHECK = 0x23


CLA = 0xE0

P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01

P2_NONE = 0x00
P2_EXTEND = 0x01 << 0
P2_MORE = 0x01 << 1

P2_IS_ATA_OR_TOKEN_ACCOUNT = 0x01 << 3

PUBLIC_KEY_LENGTH = 32

MAX_CHUNK_SIZE = 255

STATUS_OK = 0x9000

class STRUCTURE_TYPE(IntEnum):
    TRUSTED_NAME = 0x03
    TRANSACTION_CHECK = 0x09
    DYNAMIC_TOKEN = 0x90
    SOLANA_SWAP_TEMPLATE = 0x0a

class ErrorType:
    NO_APP_RESPONSE = 0x6700
    SDK_EXCEPTION = 0x6801
    SDK_INVALID_PARAMETER = 0x6802
    SDK_EXCEPTION_OVERFLOW = 0x6803
    SDK_EXCEPTION_SECURITY = 0x6804
    SDK_INVALID_CRC = 0x6805
    SDK_INVALID_CHECKSUM = 0x6806
    SDK_INVALID_COUNTER = 0x6807
    SDK_NOT_SUPPORTED = 0x6808
    SDK_INVALID_STATE = 0x6809
    SDK_TIMEOUT = 0x6810
    SDK_EXCEPTION_PIC = 0x6811
    SDK_EXCEPTION_APP_EXIT = 0x6812
    SDK_EXCEPTION_IO_OVERFLOW = 0x6813
    SDK_EXCEPTION_IO_HEADER = 0x6814
    SDK_EXCEPTION_IO_STATE = 0x6815
    SDK_EXCEPTION_IO_RESET = 0x6816
    SDK_EXCEPTION_CX_PORT = 0x6817
    SDK_EXCEPTION_SYSTEM = 0x6818
    SDK_NOT_ENOUGH_SPACE = 0x6819
    NO_APDU_RECEIVED = 0x6982
    USER_CANCEL = 0x6985
    SOLANA_INVALID_MESSAGE = 0x6a80
    SOLANA_INVALID_MESSAGE_HEADER = 0x6a81
    SOLANA_INVALID_MESSAGE_FORMAT = 0x6a82
    INVALID_INSTRUCTION_DESCRIPTOR = 0x6b00
    INVALID_TRUSTED_INFO = 0x6c00
    INVALID_DYNAMIC_TOKEN = 0x6ca0
    INVALID_TRANSACTION_CHECK = 0x6cb0
    UNIMPLEMENTED_INSTRUCTION = 0x6d00
    SOLANA_SUMMARY_FINALIZE_FAILED = 0x6f00
    SOLANA_SUMMARY_UPDATE_FAILED = 0x6f01
    SOLANA_DELAYED_PREVIEW_NOT_FOUND = 0x6f10
    SOLANA_DELAYED_HASH_MISMATCH = 0x6f11
    SOLANA_DELAYED_LENGTH_MISMATCH = 0x6f12
    SOLANA_DELAYED_DERIVATION_MISMATCH = 0x6f13
    INVALID_CLA = 0x6e00
    SOLANA_INVALID_MESSAGE_SIZE = 0x6a83
    SOLANA_INVALID_DERIVATION_PATH = 0x6a84

# https://ledgerhq.atlassian.net/wiki/spaces/TrustServices/pages/3736863735/LNS+Arch+Nano+Trusted+Names+Descriptor+Format+APIs#TLV-description
class TrustedNameTag(IntEnum):
    STRUCTURE_TYPE = 0x01
    VERSION = 0x02
    TRUSTED_NAME_TYPE = 0x70
    TRUSTED_NAME_SOURCE = 0x71
    TRUSTED_NAME = 0x20
    CHAIN_ID = 0x23
    ADDRESS = 0x22
    TRUSTED_NAME_NFT_ID = 0x72
    TRUSTED_NAME_SOURCE_CONTRACT = 0x73
    CHALLENGE = 0x12
    NOT_VALID_AFTER = 0x10
    SIGNER_KEY_ID = 0x13
    SIGNER_ALGO = 0x14
    DER_SIGNATURE = 0x15

class SolanaTokenType(IntEnum):
    TOKEN_LEGACY = 0x00
    TOKEN_2022 = 0x01

# https://ledgerhq.atlassian.net/wiki/spaces/~624b62984fe01d006ba98a93/pages/5603262535/Token+Dynamic+Descriptor#Solana
class SolanaExtensionCodeValue(IntEnum):
    MINT_CLOSE_AUTHORITY = 0X00
    TRANSFER_FEES = 0X01
    DEFAULT_ACCOUNT_STATE = 0X02
    IMMUTABLE_OWNER = 0X03
    NON_TRANSFERABLE_TOKENS = 0X04
    REQUIRED_MEMO_ON_TRANSFER = 0X05
    REALLOCATE = 0X06
    INTEREST_BEARING_TOKENS = 0X07
    PERMANENT_DELEGATE = 0X08
    CPI_GUARD = 0X09
    TRANSFER_HOOK = 0X0A
    METADATA_POINTER = 0X0B
    METADATA = 0X0C
    GROUP_POINTER = 0X0D
    GROUP = 0X0E
    MEMBER_POINTER = 0X0F
    MEMBER = 0X10

# https://ledgerhq.atlassian.net/wiki/spaces/~624b62984fe01d006ba98a93/pages/5603262535/Token+Dynamic+Descriptor#Solana
class DynamicTokenTag_TUID(IntEnum):
    TOKEN_TYPE_FLAG = 0x10
    MINT_ADDRESS = 0x11
    EXT_CODE = 0x12

# https://ledgerhq.atlassian.net/wiki/spaces/~624b62984fe01d006ba98a93/pages/5603262535/Token+Dynamic+Descriptor#Solana
class DynamicTokenTag(IntEnum):
    STRUCTURE_TYPE = 0x01
    VERSION = 0x02
    COIN_TYPE = 0x03
    APP = 0x04
    TICKER = 0x05
    MAGNITUDE = 0x06
    TUID = 0x07
    SIGNATURE = 0x08

# https://ledgerhq.atlassian.net/wiki/spaces/TA/pages/5764022544/ARCH+Solana+LiFi+swap+support

AMOUNT_RULES_ENDIANESS_MASK = (1 << 0)
AMOUNT_RULES_OFFSET_TYPE_MASK = (1 << 1)

class InstructionDescriptorTag(IntEnum):
    STRUCTURE_TYPE = 0x01
    VERSION = 0x02
    CHAIN_ID = 0x23
    TEMPLATE_ID = 0x90
    PROGRAM_ID = 0x91
    DISCRIMINATOR = 0x92
    AMOUNT_SIZE = 0x93
    AMOUNT_OFFSET = 0x94
    AMOUNT_RULES = 0x95
    ASSET_ACCOUNT_INDEX = 0x96
    ASSET_ATA_INDEX = 0x97
    RECIPIENT_ACCOUNT_INDEX = 0x98
    RECIPIENT_ATA_INDEX = 0x99
    CAPPED_AMOUNT_BPS = 0x9a
    CAPPED_AMOUNT_TOKEN_INDEX = 0x9b
    DER_SIGNATURE = 0x15

class TransactionCheckTag(IntEnum):
    STRUCTURE_TYPE = 0x01
    VERSION = 0x02
    ADDRESS = 0x22
    CHAIN_ID = 0x23
    TX_HASH = 0x27
    NORMALIZED_RISK = 0x80
    NORMALIZED_CATEGORY = 0x81
    PROVIDER_MSG = 0x82
    TINY_URL = 0x83
    SIMULATION_TYPE = 0x84
    DER_SIGNATURE = 0x15

def _extend_and_serialize_multiple_derivations_paths(derivations_paths: List[bytes]):
    serialized: bytes = len(derivations_paths).to_bytes(1, byteorder='little')
    for derivations_path in derivations_paths:
        serialized += derivations_path
    return serialized

class StatusWord(IntEnum):
    OK = 0x9000
    ERROR_NO_INFO = 0x6a00
    INVALID_DATA = 0x6a80
    INSUFFICIENT_MEMORY = 0x6a84
    INVALID_INS = 0x6d00
    INVALID_P1_P2 = 0x6b00
    CONDITION_NOT_SATISFIED = 0x6985
    REF_DATA_NOT_FOUND = 0x6a88
    EXCEPTION_OVERFLOW = 0x6807
    NOT_IMPLEMENTED = 0x911c



class SolanaClient:
    client: BackendInterface

    def __init__(self, client: BackendInterface):
        self._client = client

    def send_pki_certificate(self, partner: SigningPartner) -> RAPDU:
        return self._client.exchange_raw(partner.get_certificate_payload(self._client.device.type))

    def _exchange_split(self, cla: int, ins: int, p1: int, payload: bytes) -> RAPDU:
        if not payload:
            # Explicitly send one APDU with no data
            return self._client.exchange(cla, ins=ins, p1=p1, p2=P2_NONE, data=b"")

        payload_split = [payload[x:x + MAX_CHUNK_SIZE] for x in range(0, len(payload), MAX_CHUNK_SIZE)]
        for i, p in enumerate(payload_split):
            p2 = P2_NONE
            # Send all chunks with P2_MORE except for the last chunk
            if i != len(payload_split) - 1:
                p2 |= P2_MORE
            # Send all chunks with P2_EXTEND except for the first chunk
            if i != 0:
                p2 |= P2_EXTEND
            rapdu = self._client.exchange(CLA, ins=ins, p1=p1, p2=p2, data=p)

        return rapdu

    def provide_instruction_descriptor(self,
                                       structure_type=STRUCTURE_TYPE.SOLANA_SWAP_TEMPLATE,
                                       version=0x01,
                                       chain_id=900,
                                       template_id=0x01,
                                       program_id=bytes.fromhex("00" * 32),
                                       discriminator=b"",
                                       amount_size = 0,
                                       amount_offset = 0,
                                       amount_rules_big_endian = False,
                                       amount_rules_negative_offset = False,
                                       asset_account_index = None,
                                       asset_ata_index = None,
                                       recipient_account_index = None,
                                       recipient_ata_index = None,
                                       capped_amount_bps = None,
                                       capped_amount_token_index = None):
        amount_rules = 0
        if amount_rules_big_endian:
            amount_rules |= AMOUNT_RULES_ENDIANESS_MASK
        if amount_rules_negative_offset:
            amount_rules |= AMOUNT_RULES_OFFSET_TYPE_MASK

        payload = b""
        payload += format_tlv(InstructionDescriptorTag.STRUCTURE_TYPE, structure_type)
        payload += format_tlv(InstructionDescriptorTag.VERSION, version)
        payload += format_tlv(InstructionDescriptorTag.CHAIN_ID, chain_id)
        payload += format_tlv(InstructionDescriptorTag.TEMPLATE_ID, template_id)
        payload += format_tlv(InstructionDescriptorTag.PROGRAM_ID, program_id)
        payload += format_tlv(InstructionDescriptorTag.DISCRIMINATOR, discriminator)
        payload += format_tlv(InstructionDescriptorTag.AMOUNT_SIZE, amount_size)
        payload += format_tlv(InstructionDescriptorTag.AMOUNT_OFFSET, amount_offset)
        payload += format_tlv(InstructionDescriptorTag.AMOUNT_RULES, amount_rules)
        if asset_account_index is not None:
            payload += format_tlv(InstructionDescriptorTag.ASSET_ACCOUNT_INDEX, asset_account_index)
        if asset_ata_index is not None:
            payload += format_tlv(InstructionDescriptorTag.ASSET_ATA_INDEX, asset_ata_index)
        if recipient_account_index is not None:
            payload += format_tlv(InstructionDescriptorTag.RECIPIENT_ACCOUNT_INDEX, recipient_account_index)
        if recipient_ata_index is not None:
            payload += format_tlv(InstructionDescriptorTag.RECIPIENT_ATA_INDEX, recipient_ata_index)
        if capped_amount_bps is not None:
            payload += format_tlv(InstructionDescriptorTag.CAPPED_AMOUNT_BPS, capped_amount_bps)
        if capped_amount_token_index is not None:
            payload += format_tlv(InstructionDescriptorTag.CAPPED_AMOUNT_TOKEN_INDEX, capped_amount_token_index)
        payload += format_tlv(InstructionDescriptorTag.DER_SIGNATURE,
                              INSTRUCTION_DESCRIPTOR_PARTNER.sign(payload))

        self.send_pki_certificate(INSTRUCTION_DESCRIPTOR_PARTNER)
        self._exchange_split(CLA, INS.INS_INSTRUCTION_DESCRIPTOR, P1_NON_CONFIRM, payload)

    def enroll_ata(self, mint_address, destination_ata, destination_address):
        challenge = self.get_challenge()
        self.provide_trusted_name(mint_address,
                                  destination_ata,
                                  destination_address,
                                  # Values used across Trusted Name test
                                  101,
                                  challenge=challenge)

    def provide_trusted_name(self,
                             source_contract: bytes,
                             trusted_name: bytes,
                             address: bytes,
                             chain_id: int,
                             challenge: Optional[int] = None):
        payload = format_tlv(TrustedNameTag.STRUCTURE_TYPE, STRUCTURE_TYPE.TRUSTED_NAME)
        payload += format_tlv(TrustedNameTag.VERSION, 2)
        payload += format_tlv(TrustedNameTag.TRUSTED_NAME_TYPE, 0x06)
        payload += format_tlv(TrustedNameTag.TRUSTED_NAME_SOURCE, 0x06)
        payload += format_tlv(TrustedNameTag.TRUSTED_NAME, trusted_name)
        payload += format_tlv(TrustedNameTag.CHAIN_ID, chain_id)
        payload += format_tlv(TrustedNameTag.ADDRESS, address)
        payload += format_tlv(TrustedNameTag.TRUSTED_NAME_SOURCE_CONTRACT, source_contract)
        if challenge is not None:
            payload += format_tlv(TrustedNameTag.CHALLENGE, challenge)
        payload += format_tlv(TrustedNameTag.SIGNER_KEY_ID, 0)  # test key
        payload += format_tlv(TrustedNameTag.SIGNER_ALGO, 1)  # secp256k1
        payload += format_tlv(TrustedNameTag.DER_SIGNATURE,
                              TRUSTED_NAME_PARTNER.sign(payload))

        self.send_pki_certificate(TRUSTED_NAME_PARTNER)
        self._exchange_split(CLA, INS.INS_TRUSTED_INFO, P1_NON_CONFIRM, payload)


    def provide_dynamic_token(self,
                              ticker: str,
                              magnitude: int,
                              is_token_2022: bool,
                              mint_address: str):

        tuid = format_tlv(DynamicTokenTag_TUID.TOKEN_TYPE_FLAG, SolanaTokenType.TOKEN_2022 if is_token_2022 else SolanaTokenType.TOKEN_LEGACY)
        tuid += format_tlv(DynamicTokenTag_TUID.MINT_ADDRESS, mint_address)
        tuid += format_tlv(DynamicTokenTag_TUID.EXT_CODE, b"")

        payload = format_tlv(DynamicTokenTag.STRUCTURE_TYPE, STRUCTURE_TYPE.DYNAMIC_TOKEN)
        payload += format_tlv(DynamicTokenTag.VERSION, 1)
        payload += format_tlv(DynamicTokenTag.COIN_TYPE, 0x1F5)
        payload += format_tlv(DynamicTokenTag.APP, "Solana")
        payload += format_tlv(DynamicTokenTag.TICKER, ticker)
        payload += format_tlv(DynamicTokenTag.MAGNITUDE, magnitude)
        payload += format_tlv(DynamicTokenTag.TUID, tuid)
        payload += format_tlv(DynamicTokenTag.SIGNATURE, DYNAMIC_TOKEN_PARTNER.sign(payload))

        self.send_pki_certificate(DYNAMIC_TOKEN_PARTNER)
        self._exchange_split(CLA, INS.INS_DYNAMIC_TOKEN, P1_NON_CONFIRM, payload)


    def provide_transaction_check(self,
                                  address: bytes,
                                  tx_hash: bytes,
                                  chain_id: int,
                                  risk: int,
                                  category: int,
                                  tiny_url: str,
                                  provider_msg: str = ""):
        payload = format_tlv(TransactionCheckTag.STRUCTURE_TYPE, STRUCTURE_TYPE.TRANSACTION_CHECK)
        payload += format_tlv(TransactionCheckTag.VERSION, 1)
        payload += format_tlv(TransactionCheckTag.SIMULATION_TYPE, 0x00)  # TRANSACTION
        payload += format_tlv(TransactionCheckTag.ADDRESS, address)
        payload += format_tlv(TransactionCheckTag.TX_HASH, tx_hash)
        payload += format_tlv(TransactionCheckTag.NORMALIZED_RISK, risk)
        payload += format_tlv(TransactionCheckTag.NORMALIZED_CATEGORY, category)
        payload += format_tlv(TransactionCheckTag.TINY_URL, tiny_url)
        payload += format_tlv(TransactionCheckTag.CHAIN_ID, chain_id.to_bytes(8, 'big'))
        if provider_msg:
            payload += format_tlv(TransactionCheckTag.PROVIDER_MSG, provider_msg)
        payload += format_tlv(TransactionCheckTag.DER_SIGNATURE, sign_data(Key.TRANSACTION_CHECK, payload))

        self.send_pki_certificate(TRANSACTION_CHECK_PARTNER)

        self._exchange_split(CLA, INS.INS_TRANSACTION_CHECK, P1_NON_CONFIRM, payload)

    def send_async_transaction_check_opt_in(self):
        """Send a Transaction Check opt-in APDU (P1=0x01). Response is async (user interaction)."""
        # Send P1=0x01 with a dummy byte payload (APDU layer requires non-empty data)
        return self._client.exchange_async(CLA, INS.INS_TRANSACTION_CHECK, P1_CONFIRM, P2_NONE, bytes([0x00]))

    def request_transaction_check_opt_in(self) -> bytes:
        """Send a Transaction Check opt-in APDU (P1=0x01) synchronously.
        Returns the response data (1 byte: tx_check_enable state)."""
        rapdu: RAPDU = self._client.exchange(CLA, INS.INS_TRANSACTION_CHECK, P1_CONFIRM, P2_NONE, bytes([0x00]))
        return rapdu.data


    def get_app_configuration(self) -> bytes:
        rapdu: RAPDU = self._client.exchange(CLA, INS.INS_GET_APP_CONFIGURATION, P1_NON_CONFIRM, P2_NONE)
        return rapdu.data


    def get_challenge(self) -> bytes:
        challenge: RAPDU = self._client.exchange(CLA, INS.INS_GET_CHALLENGE,P1_NON_CONFIRM, P2_NONE)
        return challenge.data


    def get_public_key(self, derivation_path: bytes) -> bytes:
        public_key: RAPDU = self._client.exchange(CLA, INS.INS_GET_PUBKEY,
                                                  P1_NON_CONFIRM, P2_NONE,
                                                  derivation_path)
        assert len(public_key.data) == PUBLIC_KEY_LENGTH, "'from' public key size incorrect"
        return public_key.data


    @contextmanager
    def send_public_key_with_confirm(self, derivation_path: bytes) -> bytes:
        with self._client.exchange_async(CLA, INS.INS_GET_PUBKEY,
                                         P1_CONFIRM, P2_NONE,
                                         derivation_path):
            yield


    def split_and_prefix_message(self, derivation_path: bytes, message: bytes) -> List[bytes]:
        assert len(message) <= 65535, "Message to send is too long"
        header: bytes = _extend_and_serialize_multiple_derivations_paths([derivation_path])
        max_size = MAX_CHUNK_SIZE
        message_splited = [message[x:x + max_size] for x in range(0, len(message), max_size)]
        # The first chunk is the header, then all chunks with max size
        return [header] + message_splited


    def send_first_message_batch(self, ins: INS, messages: List[bytes], p1: int, user_input_is_ata_or_token_account: bool) -> RAPDU:
        self._client.exchange(CLA, ins, p1, P2_MORE, messages[0])
        p2 = P2_MORE | P2_EXTEND
        if user_input_is_ata_or_token_account:
            p2 |= P2_IS_ATA_OR_TOKEN_ACCOUNT
        for m in messages[1:]:
            self._client.exchange(CLA, ins, p1, p2, m)


    @contextmanager
    def send_async_sign_request(self,
                                ins: INS,
                                derivation_path : bytes,
                                message: bytes,
                                user_input_is_ata_or_token_account: bool = False) -> Generator[None, None, None]:
        message_splited_prefixed = self.split_and_prefix_message(derivation_path, message)

        # Send all chunks with P2_MORE except for the last chunk
        # Send all chunks with P2_EXTEND except for the first chunk
        if len(message_splited_prefixed) > 1:
            final_p2 = P2_EXTEND
            self.send_first_message_batch(ins, message_splited_prefixed[:-1], P1_CONFIRM, user_input_is_ata_or_token_account)
        else:
            final_p2 = 0

        if user_input_is_ata_or_token_account:
            final_p2 |= P2_IS_ATA_OR_TOKEN_ACCOUNT

        with self._client.exchange_async(CLA,
                                         ins,
                                         P1_CONFIRM,
                                         final_p2,
                                         message_splited_prefixed[-1]):
            yield


    @contextmanager
    def send_async_sign_message(self,
                                derivation_path : bytes,
                                message: bytes,
                                user_input_is_ata_or_token_account: bool = False) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_MESSAGE, derivation_path, message, user_input_is_ata_or_token_account):
            yield


    @contextmanager
    def send_async_sign_offchain_message(self,
                                         derivation_path : bytes,
                                         message: bytes) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_OFFCHAIN_MESSAGE, derivation_path, message):
            yield


    @contextmanager
    def send_async_sign_message_preview(self,
                                        derivation_path: bytes,
                                        message: bytes,
                                        user_input_is_ata_or_token_account: bool = False) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_MESSAGE_PREVIEW, derivation_path, message, user_input_is_ata_or_token_account):
            yield


    def sign_previewed_message(self,
                               derivation_path: bytes,
                               message: bytes,
                               user_input_is_ata_or_token_account: bool = False) -> RAPDU:
        with self.send_async_sign_request(INS.INS_SIGN_MESSAGE_DELAYED, derivation_path, message, user_input_is_ata_or_token_account):
            pass
        return self.get_async_response()


    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response

    def craft_tx(self, instructions, sender_public_key, blockhash=Hash(bytes(32))):
        message = Message.new_with_blockhash(instructions, sender_public_key, blockhash)
        tx = Transaction.new_unsigned(message)
        print(tx)
        return tx.message_data()

    def craft_v0_tx(self, instructions, sender_public_key, address_table_lookups, blockhash=Hash(bytes(32))):
        """Build a v0 versioned message from instructions + address table lookups.

        address_table_lookups is a list of tuples: (account_key_bytes_32, writable_indexes_bytes, readonly_indexes_bytes)
        """
        # Get legacy message data
        legacy_data = self.craft_tx(instructions, sender_public_key, blockhash)
        # Convert to v0: prepend version prefix, append address_table_lookups section
        version_prefix = bytes([0x80])
        alt_section = len(address_table_lookups).to_bytes(1, 'little')
        for (account_key, writable_indexes, readonly_indexes) in address_table_lookups:
            alt_section += account_key
            alt_section += len(writable_indexes).to_bytes(1, 'little')
            alt_section += bytes(writable_indexes)
            alt_section += len(readonly_indexes).to_bytes(1, 'little')
            alt_section += bytes(readonly_indexes)
        return version_prefix + legacy_data + alt_section
