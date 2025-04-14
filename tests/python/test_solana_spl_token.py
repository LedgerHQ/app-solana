import pytest
import base58
import struct

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.hash import Hash
from solders.message import Message
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from solders.instruction import Instruction, AccountMeta

from ragger.error import ExceptionRAPDU

from .apps import solana_utils as SOL
from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import verify_signature


TRANSFER_FEE_EXTENSION = 26
TRANSFER_CHECKED_WITH_FEE = 1
TRANSFER_CHECKED = 12


def craft_tx(instructions, sender_public_key):
    blockhash = Hash.default()
    message = Message.new_with_blockhash(instructions, sender_public_key, blockhash)
    tx = Transaction.new_unsigned(message)
    print(tx)
    return tx.message_data()

def enroll_ata(sol, destination_ata, destination_address):
    challenge = sol.get_challenge()
    sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
                             destination_ata,
                             destination_address,
                             # Values used across Trusted Name test
                             101,
                             challenge=challenge)

class TestTrustedName:

    def test_solana_trusted_name(self, backend, scenario_navigator):
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
        message_data = craft_tx([transfer_instruction], sender_public_key)

        sol = SolanaClient(backend)
        enroll_ata(sol, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_solana_trusted_name_create(self, backend, scenario_navigator):
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))

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
        message_data = craft_tx([create_instruction, transfer_instruction], sender_public_key)

        sol = SolanaClient(backend)
        enroll_ata(sol, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)
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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)
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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                navigation_helper.navigate_with_warning_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL


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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                navigation_helper.navigate_with_warning_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL


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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
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
        enroll_ata(sol, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)
