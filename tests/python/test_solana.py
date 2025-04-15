import pytest
from ragger.backend import RaisePolicy
from ragger.utils import RAPDU
from ragger.navigator import NavInsID
from ragger.error import ExceptionRAPDU

# from solana.transaction import Transaction, Instruction, AccountMeta

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, SOL_PACKED_DERIVATION_PATH_2, ROOT_SCREENSHOT_PATH
from .apps.solana_utils import enable_blind_signing, enable_expert_mode


class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            scenario_navigator.address_review_approve(path=ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().data == from_public_key


    def test_solana_get_public_key_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            scenario_navigator.address_review_reject(path=ROOT_SCREENSHOT_PATH)

        assert sol.get_async_response().status == ErrorType.USER_CANCEL


class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_ok_2(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_solana_simple_transfer_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigning:

    def test_ledger_sign_offchain_message_ascii_ok(self, backend, scenario_navigator):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_refused(self, backend, scenario_navigator):
        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_ascii_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_ascii_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, b"Test message")
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_2")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


    def test_ledger_sign_offchain_message_utf8_expert_ok(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_3")

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


    def test_ledger_sign_offchain_message_utf8_expert_refused(self, backend, scenario_navigator, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware, test_name + "_1")
        enable_expert_mode(navigator, backend.firmware, test_name + "_2")

        sol = SolanaClient(backend)

        offchain_message: OffchainMessage = OffchainMessage(0, bytes("Тестовое сообщение", 'utf-8'))
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            scenario_navigator.review_reject(path=ROOT_SCREENSHOT_PATH, test_name=test_name + "_3")

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

# Values used across Trusted Name test
CHAIN_ID = 101
# Token account address owner
ADDRESS = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE"
# Token account address
TRUSTED_NAME = "EQ96zptNAWwM23m5v2ByChCMTFu6zUmJgRtUrQV1uYNM"
# SPL token address (JUP Token)
SOURCE_CONTRACT = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.hash import Hash
from solders.message import Message as MessageSolders
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from .apps import solana_utils as SOL
from solders.keypair import Keypair
from solders.pubkey import Pubkey
# A bit hacky but way less hassle than actually writing an actual address decoder
SOLANA_ADDRESS_DECODER = {
    SOL.FOREIGN_ADDRESS: SOL.FOREIGN_PUBLIC_KEY,
    SOL.FOREIGN_ADDRESS_2: SOL.FOREIGN_PUBLIC_KEY_2,
}

from solders.pubkey import Pubkey
from solders.keypair import Keypair
# from solana.rpc.api import Client
# from solana.transaction import Transaction, Instruction, AccountMeta
from spl.token.constants import TOKEN_2022_PROGRAM_ID
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.transaction import Transaction
from solders.instruction import Instruction, AccountMeta
from spl.token.instructions import InstructionType
# from solders.rpc.api import Client
# from solders.rpc.config import RpcSendTransactionConfig
# from solders.rpc.responses import RpcResponse
# from solders.message import
from spl.token.constants import TOKEN_2022_PROGRAM_ID
import struct

TRANSFER_FEE_EXTENSION = 26
TRANSFER_CHECKED_WITH_FEE = 1
TRANSFER_CHECKED = 12

import base58
class TestTrustedName:

    def test_solana_trusted_name(self, backend, scenario_navigator):

        # Generate a keypair
        keypair = Keypair()

        # Extract the public key in both bytes and Base58 format
        public_key_bytes = bytes(keypair.pubkey())
        public_key_base58 = str(keypair.pubkey())
        assert Pubkey.is_on_curve(keypair.pubkey())
        print(public_key_bytes.hex())
        print(public_key_base58)
        # sol = SolanaClient(backend)

        # from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # # Create message (SPL Token transfer)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

        # with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        #     scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        # signature: bytes = sol.get_async_response().data
        # verify_signature(from_public_key, message, signature)



        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
        destination_ata = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
        ))

        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=1,
                decimals=6
            )
        )

        blockhash = Hash.default()
        message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
        tx = Transaction.new_unsigned(message)

        # Dump the message embedded in the transaction
        message_data = tx.message_data()

        sol = SolanaClient(backend)
        challenge = sol.get_challenge()

        print(f"destination_ata = {base58.b58decode(destination_ata.encode('utf-8')).hex()}")
        print(f"SOL.FOREIGN_PUBLIC_KEY = {SOL.FOREIGN_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_PUBLIC_KEY = {SOL.JUP_MINT_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_ADDRESS_STR = {SOL.JUP_MINT_ADDRESS_STR}")
        print(f"SOL.JUP_MINT_ADDRESS = {SOL.JUP_MINT_ADDRESS.hex()}")

        sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                                 # "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN".encode('utf-8'),
                                 destination_ata.encode('utf-8'),
                                 SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
                                 CHAIN_ID,
                                 challenge=challenge)

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_solana_trusted_name_create(self, backend, scenario_navigator):

        # Generate a keypair
        keypair = Keypair()

        # Extract the public key in both bytes and Base58 format
        public_key_bytes = bytes(keypair.pubkey())
        public_key_base58 = str(keypair.pubkey())
        assert Pubkey.is_on_curve(keypair.pubkey())
        print(public_key_bytes.hex())
        print(public_key_base58)
        # sol = SolanaClient(backend)

        # from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # # Create message (SPL Token transfer)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

        # with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        #     scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)

        # signature: bytes = sol.get_async_response().data
        # verify_signature(from_public_key, message, signature)



        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        destination_ata = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
        ))

        create_instruction = create_associated_token_account(
            payer=sender_ata,
            owner=Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
        )
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=1,
                decimals=6
            )
        )

        blockhash = Hash.default()
        message = MessageSolders.new_with_blockhash([create_instruction, transfer_instruction], sender_public_key, blockhash)
        tx = Transaction.new_unsigned(message)

        # Dump the message embedded in the transaction
        message_data = tx.message_data()

        sol = SolanaClient(backend)
        challenge = sol.get_challenge()

        print(f"destination_ata = {base58.b58decode(destination_ata.encode('utf-8')).hex()}")
        print(f"SOL.FOREIGN_PUBLIC_KEY = {SOL.FOREIGN_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_PUBLIC_KEY = {SOL.JUP_MINT_PUBLIC_KEY.hex()}")
        print(f"SOL.JUP_MINT_ADDRESS_STR = {SOL.JUP_MINT_ADDRESS_STR}")
        print(f"SOL.JUP_MINT_ADDRESS = {SOL.JUP_MINT_ADDRESS.hex()}")

        sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                                 # "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCNJUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN".encode('utf-8'),
                                 destination_ata.encode('utf-8'),
                                 SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
                                 CHAIN_ID,
                                 challenge=challenge)

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


def craft_tx(instructions, sender_public_key):
    blockhash = Hash.default()
    message = MessageSolders.new_with_blockhash(instructions, sender_public_key, blockhash)
    tx = Transaction.new_unsigned(message)
    print(tx)
    return tx.message_data()

class TestToken2022:
    sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
    receiver_pubkey = Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR)
    mint_pubkey = Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)

    # Compute Associated Token Accounts (ATA) manually
    sender_ata = get_associated_token_address(sender_public_key, mint_pubkey, token_program_id=TOKEN_2022_PROGRAM_ID)
    destination_ata = get_associated_token_address(receiver_pubkey, mint_pubkey, token_program_id=TOKEN_2022_PROGRAM_ID)
    str_destination_ata = str(destination_ata)
    print(f"destination_ata = {base58.b58decode(str_destination_ata.encode('utf-8')).hex()}")

    multi_sig_account = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92f")
    external_signer_1 = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92g")
    external_signer_2 = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92h")
    hook_account = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92i")

    def enroll_ata(self, sol):
        challenge = sol.get_challenge()
        sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                                 self.str_destination_ata.encode('utf-8'),
                                 SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
                                 CHAIN_ID,
                                 challenge=challenge)

    def test_transfer_checked_with_fees(self, backend, scenario_navigator):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, 100001, 6, 767)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_transfer_checked_with_0_fees(self, backend, scenario_navigator):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, 100001, 6, 0)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_no_fees_accept(self, backend, scenario_navigator, navigation_helper):
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_2022_PROGRAM_ID,
                source=self.sender_ata,
                mint=self.mint_pubkey,
                dest=self.destination_ata,
                owner=self.sender_public_key,
                amount=1,
                decimals=6
            )
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_no_fees_reject(self, backend, scenario_navigator, navigation_helper):
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_2022_PROGRAM_ID,
                source=self.sender_ata,
                mint=self.mint_pubkey,
                dest=self.destination_ata,
                owner=self.sender_public_key,
                amount=1,
                decimals=6
            )
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                navigation_helper.navigate_with_warning_and_reject()
        assert e.value.status == 0x6985


    def test_token_2022_transfer_checked_hook_and_accept_with_fees(self, backend, scenario_navigator, navigation_helper):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
            AccountMeta(pubkey=self.hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, 108, 6, 77)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_hook_and_accept_no_fees(self, backend, scenario_navigator, navigation_helper):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
            AccountMeta(pubkey=self.hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BQB", TRANSFER_CHECKED, 108, 6)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_hook_and_reject(self, backend, scenario_navigator, navigation_helper):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
            AccountMeta(pubkey=self.hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, 108, 6, 77)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                navigation_helper.navigate_with_warning_and_reject()
        assert e.value.status == 0x6985


    def test_token_2022_transfer_checked_hook_and_multi_signer(self, backend, scenario_navigator, navigation_helper):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.multi_sig_account, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.external_signer_1, is_signer=True, is_writable=False),
            AccountMeta(pubkey=self.external_signer_2, is_signer=True, is_writable=False),
            AccountMeta(pubkey=self.hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, 108, 6, 77)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_multi_signer_no_hook(self, backend, scenario_navigator, navigation_helper):
        accounts = [
            AccountMeta(pubkey=self.sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.destination_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.multi_sig_account, is_signer=False, is_writable=False),
            AccountMeta(pubkey=self.external_signer_1, is_signer=True, is_writable=False),
            AccountMeta(pubkey=self.external_signer_2, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, 108, 6, 77)
        )
        message_data = craft_tx([transfer_instruction], self.sender_public_key)

        sol = SolanaClient(backend)
        self.enroll_ata(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)
