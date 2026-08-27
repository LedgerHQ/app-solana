import pytest
import base58
import struct

from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.hash import Hash
from solders.message import Message
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.instructions import transfer_checked, get_associated_token_address, create_associated_token_account
from spl.token.models import TransferCheckedParams
from solders.instruction import Instruction, AccountMeta
from solders.system_program import create_account, CreateAccountParams
from solders.sysvar import RENT

from ragger.error import ExceptionRAPDU

from application_client import solana_utils as SOL
from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import verify_signature, PROGRAM_ID_SYSTEM


TRANSFER_FEE_EXTENSION = 26
TRANSFER_CHECKED_WITH_FEE = 1
TRANSFER_CHECKED = 12

DEFAULT_ACCOUNT_STATE_EXTENSION = 28
DEFAULT_ACCOUNT_STATE_UPDATE = 1
ACCOUNT_STATE_FROZEN = 2

SYSTEM_TRANSFER = 2

class TestSPL:

    def test_solana_create_account(self, sol, scenario_navigator, root_pytest_dir):
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))

        create_instruction = create_associated_token_account(
            payer=sender_ata,
            owner=Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
        )

        message_data = sol.craft_tx([create_instruction], sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

class TestTrustedName:

    def test_solana_trusted_name(self, sol, scenario_navigator, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_solana_trusted_name_create(self, sol, scenario_navigator, root_pytest_dir):
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

        message_data = sol.craft_tx([create_instruction, transfer_instruction], sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_solana_trusted_name_ata_input(self, sol, scenario_navigator, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data, user_input_is_ata_or_token_account=True):
            scenario_navigator.review_approve(path=root_pytest_dir)
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

    def test_transfer_checked_with_fees(self, sol, scenario_navigator, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_transfer_checked_with_0_fees(self, sol, scenario_navigator, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_no_fees_accept(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_no_fees_reject(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                navigation_helper.navigate_with_warning_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL


    def test_token_2022_transfer_checked_hook_and_accept_with_fees(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_hook_and_accept_no_fees(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_hook_and_reject(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                navigation_helper.navigate_with_warning_and_reject()
        assert e.value.status == ErrorType.USER_CANCEL


    def test_token_2022_transfer_checked_hook_and_multi_signer(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_warning_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


    def test_token_2022_transfer_checked_multi_signer_no_hook(self, sol, scenario_navigator, navigation_helper, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_token_2022_create(self, sol, scenario_navigator, root_pytest_dir):
        create_instruction = create_associated_token_account(
            payer=self.sender_ata,
            owner=self.receiver_pubkey,
            mint=self.mint_pubkey,
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )
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

        message_data = sol.craft_tx([create_instruction, transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, self.str_destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def _craft_default_account_state_tx(self, sol):
        system_transfer_instruction = Instruction(
            program_id=Pubkey.from_string(PROGRAM_ID_SYSTEM),
            accounts=[
                AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.receiver_pubkey, is_signer=False, is_writable=True),
            ],
            data=struct.pack("<IQ", SYSTEM_TRANSFER, 1),
        )
        update_default_state_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
            ],
            data=struct.pack("<BBB", DEFAULT_ACCOUNT_STATE_EXTENSION, DEFAULT_ACCOUNT_STATE_UPDATE, ACCOUNT_STATE_FROZEN),
        )
        return sol.craft_tx([system_transfer_instruction, update_default_state_instruction], self.sender_public_key)

    def test_token_2022_default_account_state_warns_and_accept(self, sol, scenario_navigator, root_pytest_dir):
        message_data = self._craft_default_account_state_tx(sol)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_token_2022_default_account_state_alone_warns_on_blind_signing(self, sol, navigation_helper):
        """The extension instruction is not displayed, so a message holding nothing else has
        nothing left to clear sign and falls back to blind signing. The extension warning
        applies to that screen too."""
        update_default_state_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=self.mint_pubkey, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
            ],
            data=struct.pack("<BBB", DEFAULT_ACCOUNT_STATE_EXTENSION, DEFAULT_ACCOUNT_STATE_UPDATE, ACCOUNT_STATE_FROZEN),
        )
        navigation_helper.enable_blind_signing()
        message_data = sol.craft_tx([update_default_state_instruction], self.sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            navigation_helper.navigate_with_blind_signing_and_accept()
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


class TestTokenDynamic:
    def test_dynamic_token_simple(self, sol, scenario_navigator, root_pytest_dir):
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR))
        destination_ata = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR)
        ))

        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=1,
                decimals=6
            )
        )

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False, mint_address=SOL.GORK_MINT_ADDRESS)
        sol.enroll_ata(SOL.GORK_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_dynamic_token_address_mismatch_address(self, sol, scenario_navigator, root_pytest_dir):
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR))
        destination_ata = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR)
        ))

        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=1,
                decimals=6
            )
        )

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False, mint_address=SOL.JUP_MINT_ADDRESS)
        sol.enroll_ata(SOL.GORK_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_dynamic_token_address_mismatch_token_kind(self, sol, scenario_navigator, root_pytest_dir):
        # Get the sender public key
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR))
        destination_ata = str(get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
            Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR)
        ))

        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.GORK_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=sender_public_key,
                amount=1,
                decimals=6
            )
        )

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=True, mint_address=SOL.GORK_MINT_ADDRESS_STR)
        sol.enroll_ata(SOL.GORK_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_dynamic_token_address_priority(self, sol, scenario_navigator, root_pytest_dir):
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

        message_data = sol.craft_tx([transfer_instruction], sender_public_key)
        sol.provide_dynamic_token(ticker="JUP_override", magnitude=6, is_token_2022=False, mint_address=SOL.JUP_MINT_ADDRESS_STR)
        sol.enroll_ata(SOL.JUP_MINT_ADDRESS, destination_ata.encode('utf-8'), SOL.FOREIGN_ADDRESS_STR.encode('utf-8'))

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)


# The signer set is arbitrary, only the identities displayed during review matter here
MULTISIG_SIGNER_ADDRESSES = [
    "AxmUF3qkdz1zs151Q5WttVMkFpFGQPwghZs4d1mwY55d",
    "26pV97Ce83ZQ6Kz9XT4td8tdoUFPTng8Fb8gPyc53dJx",
    "CpfvLiiPALdzZTP3fUrALg2TXwEDSAknRh1sn5JCt9Sr",
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "38PgzpJYu2HkiYvV8qePFakB8tuobPdGm2FFEn7Dpump",
    "So11111111111111111111111111111111111111112",
    "SysvarC1ock11111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
]

MULTISIG_ACCOUNT_STR = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
MULTISIG_ACCOUNT_SIZE = 355
MULTISIG_RENT_LAMPORTS = 2039280

INITIALIZE_MULTISIG = 2


def _initialize_multisig_instruction(multisig, signers, m, program_id=TOKEN_PROGRAM_ID):
    accounts = [
        AccountMeta(pubkey=multisig, is_signer=False, is_writable=True),
        AccountMeta(pubkey=RENT, is_signer=False, is_writable=False),
    ]
    for signer in signers:
        accounts.append(AccountMeta(pubkey=signer, is_signer=False, is_writable=False))

    return Instruction(
        program_id=program_id,
        accounts=accounts,
        data=struct.pack("<BB", INITIALIZE_MULTISIG, m),
    )


class TestMultisig:

    def _signers(self, count):
        return [Pubkey.from_string(address) for address in MULTISIG_SIGNER_ADDRESSES[:count]]

    def test_solana_initialize_multisig(self, sol, scenario_navigator, root_pytest_dir):
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        multisig = Pubkey.from_string(MULTISIG_ACCOUNT_STR)

        instruction = _initialize_multisig_instruction(multisig, self._signers(3), 2)

        message_data = sol.craft_tx([instruction], sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_solana_initialize_multisig_2022(self, sol, scenario_navigator, root_pytest_dir):
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        multisig = Pubkey.from_string(MULTISIG_ACCOUNT_STR)

        instruction = _initialize_multisig_instruction(multisig,
                                                       self._signers(3),
                                                       2,
                                                       program_id=TOKEN_2022_PROGRAM_ID)

        message_data = sol.craft_tx([instruction], sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_solana_initialize_multisig_max_signers(self, sol, scenario_navigator, root_pytest_dir):
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        multisig = Pubkey.from_string(MULTISIG_ACCOUNT_STR)

        instruction = _initialize_multisig_instruction(multisig, self._signers(11), 11)

        message_data = sol.craft_tx([instruction], sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_solana_create_multisig(self, sol, scenario_navigator, root_pytest_dir):
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        multisig = Pubkey.from_string(MULTISIG_ACCOUNT_STR)

        create_instruction = create_account(
            CreateAccountParams(
                from_pubkey=sender_public_key,
                to_pubkey=multisig,
                lamports=MULTISIG_RENT_LAMPORTS,
                space=MULTISIG_ACCOUNT_SIZE,
                owner=TOKEN_PROGRAM_ID,
            )
        )
        initialize_instruction = _initialize_multisig_instruction(multisig, self._signers(3), 2)

        message_data = sol.craft_tx([create_instruction, initialize_instruction], sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            scenario_navigator.review_approve(path=root_pytest_dir)
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def test_solana_initialize_multisig_refused(self, sol, scenario_navigator, root_pytest_dir):
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        multisig = Pubkey.from_string(MULTISIG_ACCOUNT_STR)

        instruction = _initialize_multisig_instruction(multisig, self._signers(3), 2)

        message_data = sol.craft_tx([instruction], sender_public_key)
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                scenario_navigator.review_reject(path=root_pytest_dir)
        assert e.value.status == ErrorType.USER_CANCEL

    def _check_multisig_not_clear_signed(self, sol, signers, m):
        sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)
        multisig = Pubkey.from_string(MULTISIG_ACCOUNT_STR)

        instruction = _initialize_multisig_instruction(multisig, signers, m)

        # The parser refuses the instruction, so the message can only be blind signed, and blind
        # signing is disabled by default
        message_data = sol.craft_tx([instruction], sender_public_key)
        with pytest.raises(ExceptionRAPDU) as e:
            with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
                pass
        assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

    def test_solana_initialize_multisig_threshold_above_signer_count(self, sol):
        # A 4 of 3 multisig can never reach its threshold
        self._check_multisig_not_clear_signed(sol, self._signers(3), 4)

    def test_solana_initialize_multisig_zero_threshold(self, sol):
        self._check_multisig_not_clear_signed(sol, self._signers(3), 0)

    def test_solana_initialize_multisig_no_signer(self, sol):
        self._check_multisig_not_clear_signed(sol, [], 1)
