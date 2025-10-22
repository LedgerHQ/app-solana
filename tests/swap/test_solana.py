import pytest
import struct
import base58
from ragger.error import ExceptionRAPDU

from ledger_app_clients.exchange.test_runner import ExchangeTestRunner, ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES
from application_client.solana import SolanaClient, ErrorType
from application_client.solana_cmd_builder import SystemInstructionTransfer, ComputeBudgetInstructionSetComputeUnitLimit, ComputeBudgetInstructionSetComputeUnitPrice, verify_signature
from application_client.solana_cmd_builder import Message as MessageCustom
from application_client.solana_utils import sol_to_lamports, lamports_to_bytes
from application_client import solana_utils as SOL

from . import cal_helper as cal

from solders.pubkey import Pubkey
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, create_associated_token_account
from solders.instruction import Instruction, AccountMeta

# A bit hacky but way less hassle than actually writing an actual address decoder
SOLANA_ADDRESS_DECODER = {
    SOL.FOREIGN_ADDRESS: SOL.FOREIGN_PUBLIC_KEY,
    SOL.FOREIGN_ADDRESS_2: SOL.FOREIGN_PUBLIC_KEY_2,
}

FEES = sol_to_lamports(0.002123)
FEES_BYTES = lamports_to_bytes(FEES)

FEES_2 = sol_to_lamports(0.005543)
FEES_2_BYTES = lamports_to_bytes(FEES_2)

TRANSFER_FEE_EXTENSION = 26
TRANSFER_CHECKED_WITH_FEE = 1
TRANSFER_CHECKED = 12

# ExchangeTestRunner implementation for Solana
class GenericSolanaTests(ExchangeTestRunner):
    currency_configuration = cal.SOL_CURRENCY_CONFIGURATION
    valid_destination_1 = SOL.FOREIGN_ADDRESS
    valid_destination_2 = SOL.FOREIGN_ADDRESS_2
    valid_refund = SOL.OWNED_ADDRESS
    valid_send_amount_1 = SOL.AMOUNT
    valid_send_amount_2 = SOL.AMOUNT_2
    valid_fees_1 = FEES
    valid_fees_2 = FEES_2
    fake_refund = SOL.FOREIGN_ADDRESS
    fake_payout = SOL.FOREIGN_ADDRESS
    signature_refusal_error_code = ErrorType.SOLANA_SUMMARY_FINALIZE_FAILED

    partner_name = "Partner name"
    fund_user_id = "Daft Punk"
    fund_account_name = "Account 0"

    sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

    def perform_final_tx(self, destination, send_amount, fees, memo):
        decoded_destination = SOLANA_ADDRESS_DECODER[destination]
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(SOL.OWNED_PUBLIC_KEY, decoded_destination, send_amount)
        message: bytes = MessageCustom([instruction]).serialize()
        sol = SolanaClient(self.backend)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)


# Use a class to reuse the same Speculos instance
class TestsSolana:

    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana(self, backend, exchange_navigation_helper, test_to_run):
        GenericSolanaTests(backend, exchange_navigation_helper).run_test(test_to_run)

# ExchangeTestRunner implementation for Solana
class SolanaPriorityFeesTests(GenericSolanaTests):
    def perform_final_tx(self, destination, send_amount, fees, memo):
        decoded_destination = SOLANA_ADDRESS_DECODER[destination]
        computeUnitLimit: ComputeBudgetInstructionSetComputeUnitLimit = ComputeBudgetInstructionSetComputeUnitLimit(300)
        computeUnitPrice: ComputeBudgetInstructionSetComputeUnitPrice = ComputeBudgetInstructionSetComputeUnitPrice(20000)
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(SOL.OWNED_PUBLIC_KEY, decoded_destination, send_amount)
        message: bytes = MessageCustom([computeUnitLimit, computeUnitPrice, instruction]).serialize()
        sol = SolanaClient(self.backend)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)


# Use a class to reuse the same Speculos instance
class TestsSolanaPriorityFees:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_priority_fees(self, backend, exchange_navigation_helper, test_to_run):
        SolanaPriorityFeesTests(backend, exchange_navigation_helper).run_test(test_to_run)

class SPLTokenTests(GenericSolanaTests):
    currency_configuration = cal.SOL_USDC_CURRENCY_CONFIGURATION

    valid_destination_1 = "JA2zDGUjCJePxBWbW895rMPUSBPPU15Q5UbqspezSzwF"
    valid_destination_2 = str(
        get_associated_token_address(
            Pubkey.from_string(SOL.FOREIGN_ADDRESS_2_STR),
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR)
        )
    )
    valid_refund = SOL.OWNED_ADDRESS

    valid_send_amount_1 = SOL.AMOUNT
    valid_send_amount_2 = SOL.AMOUNT_2
    valid_fees_1 = FEES
    valid_fees_2 = FEES_2
    fake_refund = SOL.FOREIGN_ADDRESS_STR
    fake_payout = SOL.FOREIGN_ADDRESS_STR
    signature_refusal_error_code = ErrorType.SOLANA_SUMMARY_FINALIZE_FAILED

    def perform_final_tx(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR)
            )
        )

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(self.sender_public_key, Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR))

        # Create the transaction

        create_instruction = create_associated_token_account(
            payer=sender_ata,
            owner=Pubkey.from_string(destination),
            mint=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
        )
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=self.sender_public_key,
                amount=send_amount,
                decimals=6  # Number of decimals for USDC token
            )
        )

        sol = SolanaClient(self.backend)
        message_data = sol.craft_tx([create_instruction, transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

# Use a class to reuse the same Speculos instance
class TestsSPLToken:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_spl_token(self, backend, exchange_navigation_helper, test_to_run):
        SPLTokenTests(backend, exchange_navigation_helper).run_test(test_to_run)
        # message: bytes = bytes.fromhex("0100030621a36fe74e1234c35e62bfd700fd247b92c4d4e0e538401ac51f5c4ae97657a7276497ba0bb8659172b72edd8c66e18f561764d9c86a610a3a7e0f79c0baf9dbc71573813ea96479a79e579af14646413602b9b3dcbdc51cbf8e064b5685ed120479d9c7cc1035de7211f99eb48c09d70b2bdf5bdf9e2e56b8a1fbb5a2ea332706ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a938b19525b109c0e2517df8786389e33365afe2dc6bfabeb65458fd24a1ab5b13000000000000000000000000000000000000000000000000000000000000000001040501030205000a0c020000000000000006")

class SPLToken2022Tests(SPLTokenTests):
    def perform_final_tx(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            self.sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(destination_ata), is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, send_amount, 6, 0)
        )

        sol = SolanaClient(self.backend)
        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx_with_transfer_fees(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            self.sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(destination_ata), is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, send_amount, 6, 767)
        )

        sol = SolanaClient(self.backend)
        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx_with_unknown_transfer_fees(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        # Get the sender public key

        # Get the associated token addresses for the sender
        sender_ata = get_associated_token_address(
            self.sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )

        # Create the transaction
        transfer_instruction = transfer_checked(
            TransferCheckedParams(
                program_id=TOKEN_2022_PROGRAM_ID,
                source=sender_ata,
                mint=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                dest=Pubkey.from_string(destination_ata),
                owner=self.sender_public_key,
                amount=send_amount,
                decimals=6  # Number of decimals for USDC token
            )
        )

        sol = SolanaClient(self.backend)
        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx_with_transfer_hook(self, destination, send_amount, fees, memo):
        destination_ata = str(
            get_associated_token_address(
                Pubkey.from_string(destination),
                Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
                token_program_id=TOKEN_2022_PROGRAM_ID,
            )
        )
        sender_ata = get_associated_token_address(
            self.sender_public_key,
            Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR),
            token_program_id=TOKEN_2022_PROGRAM_ID,
        )
        hook_account = Pubkey.from_string("FcheSyMboM2FKxieZPsT7r69s5UunZiK8tNSmSKts92i")

        accounts = [
            AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(SOL.USDC_MINT_ADDRESS_STR), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(destination_ata), is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=False),
            AccountMeta(pubkey=hook_account, is_signer=False, is_writable=True),
        ]
        transfer_instruction = Instruction(
            program_id=TOKEN_2022_PROGRAM_ID,
            accounts=accounts,
            data=struct.pack("<BBQBQ", TRANSFER_FEE_EXTENSION, TRANSFER_CHECKED_WITH_FEE, send_amount, 6, 0)
        )

        sol = SolanaClient(self.backend)
        message_data = sol.craft_tx([transfer_instruction], self.sender_public_key)
        sol.enroll_ata(SOL.USDC_MINT_ADDRESS, destination_ata.encode('utf-8'), destination.encode('utf-8'))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

# Use a class to reuse the same Speculos instance
class TestsSPLToken2022:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_spl_token_2022(self, backend, exchange_navigation_helper, test_to_run):
        SPLToken2022Tests(backend, exchange_navigation_helper).run_test(test_to_run)

    def test_solana_spl_token_2022_token_fees(self, backend, exchange_navigation_helper):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SPLToken2022Tests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_with_transfer_fees
            test_class.run_test("swap_valid_1")
        assert e.value.status == test_class.signature_refusal_error_code

    def test_solana_spl_token_2022_unknown_token_fees(self, backend, exchange_navigation_helper):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SPLToken2022Tests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_with_unknown_transfer_fees
            test_class.run_test("swap_valid_1")
        assert e.value.status == test_class.signature_refusal_error_code

    def test_solana_spl_token_2022_token_hook(self, backend, exchange_navigation_helper):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SPLToken2022Tests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_with_transfer_hook
            test_class.run_test("swap_valid_1")
        assert e.value.status == test_class.signature_refusal_error_code

class SolanaDescriptorTests(SPLTokenTests):
    currency_configuration = cal.GORK_CURRENCY_CONFIGURATION

    # Previously used amount does not fit on 4 bytes while we want to test the 4 bytes descriptor
    valid_send_amount_2 = sol_to_lamports(0.000001234)
    custom_program_id_string = "3KS2k14CmtnuVv2fvYcvdrNgC94Y11WETBpMUGgXyWZL"
    custom_program_id = Pubkey.from_string(custom_program_id_string)
    decoded_custom_program_id_string = base58.b58decode(custom_program_id_string)

    def _perform_final_lifi_transaction(self, sol, destination, send_amount, is_token_2022, mint_address_str):
        mint_pubkey = Pubkey.from_string(mint_address_str)
        receiver_pubkey = Pubkey.from_string(destination)
        if is_token_2022:
            token_program_id = TOKEN_2022_PROGRAM_ID
        else:
            token_program_id = TOKEN_PROGRAM_ID
        destination_ata_pubkey = get_associated_token_address(receiver_pubkey, mint_pubkey, token_program_id=token_program_id)
        dummy_storage_account = Pubkey.from_string("EHsACWBhgmw8iq5dmUZzTA1esRqcTognhKNHUkPi4q4g")
        sender_ata = get_associated_token_address(self.sender_public_key, mint_pubkey, token_program_id=token_program_id)

        instructions_list = []

        # Instruction with everything to check
        discriminator_8_bytes = 0x0102030405060708
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            # Random order of accounts, all checked
            accounts=[
                AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True),
                AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=False), # asset_ata_index
                AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                AccountMeta(pubkey=receiver_pubkey, is_signer=False, is_writable=False), # recipient_account_index
                AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                AccountMeta(pubkey=mint_pubkey, is_signer=False, is_writable=False), # asset_account_index
                AccountMeta(pubkey=destination_ata_pubkey, is_signer=False, is_writable=False), # recipient_ata_index
            ],
            data=struct.pack("<QQ", discriminator_8_bytes, send_amount),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           discriminator=discriminator_8_bytes.to_bytes(8, byteorder='little'),
                                           program_id=self.decoded_custom_program_id_string,
                                           amount_size=8,
                                           amount_offset=8,
                                           asset_account_index=5,
                                           asset_ata_index=1,
                                           recipient_account_index=3,
                                           recipient_ata_index=6)

        # 1 byte discriminator
        discriminator_1_bytes = 0xAB
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<B", discriminator_1_bytes),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           discriminator=discriminator_1_bytes.to_bytes(1, byteorder='little'),
                                           program_id=self.decoded_custom_program_id_string)

        # 4 bytes discriminator
        discriminator_4_bytes = 0xABCDEF07
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<L", discriminator_4_bytes),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           discriminator=discriminator_4_bytes.to_bytes(4, byteorder='little'),
                                           program_id=self.decoded_custom_program_id_string)

        # Little endian amount 4 bytes
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<L", send_amount),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           program_id=self.decoded_custom_program_id_string,
                                           amount_size=4,
                                           amount_offset=0,
                                           amount_rules_big_endian=False,
                                           amount_rules_negative_offset=False)

        # Little endian amount 8 bytes offset
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<QQQ", 0, 0, send_amount),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           program_id=self.decoded_custom_program_id_string,
                                           amount_size=8,
                                           amount_offset=8 * 2,
                                           amount_rules_big_endian=False,
                                           amount_rules_negative_offset=False)

        # Big endian amount 8 bytes
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack(">Q", send_amount),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           program_id=self.decoded_custom_program_id_string,
                                           amount_size=8,
                                           amount_offset=0,
                                           amount_rules_big_endian=True,
                                           amount_rules_negative_offset=False)

        # Big endian amount 4 bytes reverse offset
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack(">QLQQQ", 0, send_amount, 0, 0, 0),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           program_id=self.decoded_custom_program_id_string,
                                           amount_size=4,
                                           amount_offset=8*3 + 4,
                                           amount_rules_big_endian=True,
                                           amount_rules_negative_offset=True)

        # Nothing to check * 2
        for i in range(2):
            instructions_list.append(Instruction(
                program_id=self.custom_program_id,
                accounts=[
                    AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                    AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                    AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                ],
                data=struct.pack("QQQ", 0, 0, 0),
            ))
            sol.provide_instruction_descriptor(template_id=2**64-1,
                                               program_id=self.decoded_custom_program_id_string)

        # Other order of accounts
        instructions_list.append(Instruction(
            program_id=self.custom_program_id,
            accounts=[
                AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True),
                AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                AccountMeta(pubkey=mint_pubkey, is_signer=False, is_writable=False), # asset_account_index
                AccountMeta(pubkey=destination_ata_pubkey, is_signer=False, is_writable=False), # recipient_ata_index
                AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
                AccountMeta(pubkey=sender_ata, is_signer=False, is_writable=False), # asset_ata_index
                AccountMeta(pubkey=receiver_pubkey, is_signer=False, is_writable=False), # recipient_account_index
                AccountMeta(pubkey=dummy_storage_account, is_signer=False, is_writable=True), # noise
            ],
            data=struct.pack("B", 0),
        ))
        sol.provide_instruction_descriptor(template_id=2**64-1,
                                           program_id=self.decoded_custom_program_id_string,
                                           asset_account_index=2,
                                           asset_ata_index=5,
                                           recipient_account_index=6,
                                           recipient_ata_index=3)

        message_data = sol.craft_tx(instructions_list, self.sender_public_key)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message_data):
            pass
        signature: bytes = sol.get_async_response().data
        verify_signature(SOL.OWNED_PUBLIC_KEY, message_data, signature)

    def perform_final_tx(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False, mint_address=SOL.GORK_MINT_ADDRESS)
        self._perform_final_lifi_transaction(sol, destination, send_amount, False, SOL.GORK_MINT_ADDRESS_STR)

    # Variant of above pretending GORK is a token 2022. Not an issue for the application
    def perform_final_tx_2022(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=True, mint_address=SOL.GORK_MINT_ADDRESS)
        self._perform_final_lifi_transaction(sol, destination, send_amount, True, SOL.GORK_MINT_ADDRESS_STR)

    # Variant of above relying on application side hardcoded token list
    def perform_final_tx_hardcoded_token(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        self._perform_final_lifi_transaction(sol, destination, send_amount, False, SOL.USDC_MINT_ADDRESS_STR)

    def perform_final_tx_bad_structure_type(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(structure_type=0x00)

    def perform_final_tx_bad_version(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(version=0x02)

    def perform_final_tx_bad_chain_id(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(chain_id=800)

    def perform_final_tx_bad_size_program_id_too_small(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(program_id=bytes.fromhex("00" * 31))

    def perform_final_tx_bad_size_program_id_too_big(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(program_id=bytes.fromhex("00" * 33))

    def perform_final_tx_discriminator_too_big(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(discriminator=bytes.fromhex("00" * 9))

    def perform_final_tx_too_many_descriptors(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        for x in range(11):
            sol.provide_instruction_descriptor()

    def perform_final_tx_mismatch_template(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(template_id=1)
        sol.provide_instruction_descriptor(template_id=2)

    def perform_final_tx_mismatch_network(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(chain_id=900)
        sol.provide_instruction_descriptor(chain_id=901)

    def perform_final_tx_no_descriptor(self, destination, send_amount, fees, memo):
        instruction = Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<B", 0x01)
        )

        sol = SolanaClient(self.backend)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, sol.craft_tx([instruction], self.sender_public_key)):
            pass

    def perform_final_tx_mismatch_descriptor_count(self, destination, send_amount, fees, memo):
        instruction = Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<B", 0x01)
        )

        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string)
        sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, sol.craft_tx([instruction], self.sender_public_key)):
            pass

    def perform_final_tx_mismatch_program_id(self, destination, send_amount, fees, memo):
        instruction = Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<B", 0x01)
        )

        sol = SolanaClient(self.backend)
        # Random wrong program id
        sol.provide_instruction_descriptor(program_id=base58.b58decode("EHsACWBhgmw8iq5dmUZzTA1esRqcTognhKNHUkPi4q4g"))
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, sol.craft_tx([instruction], self.sender_public_key)):
            pass

    def _perform_final_tx_discriminator_issue(self, final_discriminator):
        instruction = Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<B", 0x01)
        )

        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string, discriminator=final_discriminator)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, sol.craft_tx([instruction], self.sender_public_key)):
            pass

    def perform_final_tx_mismatch_discriminator_too_small(self, destination, send_amount, fees, memo):
        self._perform_final_tx_discriminator_issue(final_discriminator=bytes.fromhex("0001"))

    def perform_final_tx_mismatch_discriminator_value(self, destination, send_amount, fees, memo):
        self._perform_final_tx_discriminator_issue(final_discriminator=bytes.fromhex("04"))

    def _perform_final_tx_amount_issue(self, amount_size, amount_offset, amount_rules_negative_offset):
        instruction = Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<BQ", 0x01, 42_000)
        )

        sol = SolanaClient(self.backend)
        sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string, amount_size=amount_size, amount_offset=amount_offset, amount_rules_negative_offset=amount_rules_negative_offset)
        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, sol.craft_tx([instruction], self.sender_public_key)):
            pass

    def perform_final_tx_amount_size_too_big(self, destination, send_amount, fees, memo):
        self._perform_final_tx_amount_issue(amount_size=9, amount_offset=1, amount_rules_negative_offset=False)

    def perform_final_tx_offset_out_of_bounds(self, destination, send_amount, fees, memo):
        self._perform_final_tx_amount_issue(amount_size=8, amount_offset=100, amount_rules_negative_offset=False)

    def perform_final_tx_size_plus_offset_out_of_bounds(self, destination, send_amount, fees, memo):
        self._perform_final_tx_amount_issue(amount_size=8, amount_offset=2, amount_rules_negative_offset=False)

    def perform_final_tx_negative_offset_underflow(self, destination, send_amount, fees, memo):
        self._perform_final_tx_amount_issue(amount_size=8, amount_offset=5, amount_rules_negative_offset=True)

    def _perform_final_tx_index_issue(self, field_to_check, index):
        instruction = Instruction(
            program_id=self.custom_program_id,
            accounts=[AccountMeta(pubkey=self.sender_public_key, is_signer=True, is_writable=True)],
            data=struct.pack("<BQ", 0x01, 42_000),
        )

        sol = SolanaClient(self.backend)
        if field_to_check == "asset_account_index":
            sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string, asset_account_index=index)
        elif field_to_check == "asset_ata_index":
            sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string, asset_ata_index=index)
        elif field_to_check == "recipient_account_index":
            sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string, recipient_account_index=index)
        elif field_to_check == "recipient_ata_index":
            sol.provide_instruction_descriptor(program_id=self.decoded_custom_program_id_string, recipient_ata_index=index)

        with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, sol.craft_tx([instruction], self.sender_public_key)):
            pass

    def perform_final_tx_index_issue_oob_asset_account_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="asset_account_index", index=1)

    def perform_final_tx_index_issue_oob_asset_ata_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="asset_ata_index", index=1)

    def perform_final_tx_index_issue_oob_recipient_account_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="recipient_account_index", index=1)

    def perform_final_tx_index_issue_oob_recipient_ata_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="recipient_ata_index", index=1)

    def perform_final_tx_index_issue_mismatch_asset_account_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="asset_account_index", index=0)

    def perform_final_tx_index_issue_mismatch_asset_ata_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="asset_ata_index", index=0)

    def perform_final_tx_index_issue_mismatch_recipient_account_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="recipient_account_index", index=0)

    def perform_final_tx_index_issue_mismatch_recipient_ata_index(self, destination, send_amount, fees, memo):
        self._perform_final_tx_index_issue(field_to_check="recipient_ata_index", index=0)

    def perform_final_tx_no_token_info(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        self._perform_final_lifi_transaction(sol, destination, send_amount, False, SOL.GORK_MINT_ADDRESS_STR)

    def perform_final_tx_mismatch_token_2022(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=True, mint_address=SOL.GORK_MINT_ADDRESS)
        self._perform_final_lifi_transaction(sol, destination, send_amount, False, SOL.GORK_MINT_ADDRESS_STR)

    def perform_final_tx_mismatch_token_2022_variant(self, destination, send_amount, fees, memo):
        sol = SolanaClient(self.backend)
        sol.provide_dynamic_token(ticker="GORK", magnitude=6, is_token_2022=False, mint_address=SOL.GORK_MINT_ADDRESS)
        self._perform_final_lifi_transaction(sol, destination, send_amount, True, SOL.GORK_MINT_ADDRESS_STR)

# Use a class to reuse the same Speculos instance
class TestsSolanaDescriptor:
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_solana_descriptor(self, backend, exchange_navigation_helper, test_to_run):
        SolanaDescriptorTests(backend, exchange_navigation_helper).run_test(test_to_run)

    # Let's only test the main valid case for edge token cases, no need to check amount mismatch and so on
    def test_solana_descriptor_2022(self, backend, exchange_navigation_helper):
        test_class = SolanaDescriptorTests(backend, exchange_navigation_helper)
        test_class.perform_final_tx = test_class.perform_final_tx_2022
        test_class.run_test("swap_valid_1")

    def test_solana_descriptor_hardcoded_token(self, backend, exchange_navigation_helper):
        test_class = SolanaDescriptorTests(backend, exchange_navigation_helper)
        test_class.currency_configuration = cal.SOL_USDC_CURRENCY_CONFIGURATION
        test_class.perform_final_tx = test_class.perform_final_tx_hardcoded_token
        test_class.run_test("swap_valid_1")

    # Errors detected at discriminator reception
    @pytest.mark.parametrize('fault_test_to_run', [
        "perform_final_tx_bad_structure_type",
        "perform_final_tx_bad_version",
        "perform_final_tx_bad_chain_id",
        "perform_final_tx_bad_size_program_id_too_small",
        "perform_final_tx_bad_size_program_id_too_big",
        "perform_final_tx_discriminator_too_big",
        "perform_final_tx_too_many_descriptors",
        "perform_final_tx_mismatch_template",
        "perform_final_tx_mismatch_network",
    ])
    def test_lifi_bad_descriptor(self, backend, exchange_navigation_helper, fault_test_to_run):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SolanaDescriptorTests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = getattr(test_class, fault_test_to_run)
            test_class.run_test("swap_valid_1")
        assert e.value.status == ErrorType.INVALID_INSTRUCTION_DESCRIPTOR

    # Errors detected at tx reception and discriminator usage
    @pytest.mark.parametrize('fault_test_to_run', [
        "perform_final_tx_no_descriptor",
        "perform_final_tx_mismatch_descriptor_count",
        "perform_final_tx_mismatch_program_id",
        "perform_final_tx_mismatch_discriminator_too_small",
        "perform_final_tx_mismatch_discriminator_value",
        "perform_final_tx_amount_size_too_big",
        "perform_final_tx_offset_out_of_bounds",
        "perform_final_tx_size_plus_offset_out_of_bounds",
        "perform_final_tx_negative_offset_underflow",
        "perform_final_tx_index_issue_oob_asset_account_index",
        "perform_final_tx_index_issue_oob_asset_ata_index",
        "perform_final_tx_index_issue_oob_recipient_account_index",
        "perform_final_tx_index_issue_oob_recipient_ata_index",
        "perform_final_tx_index_issue_mismatch_asset_account_index",
        "perform_final_tx_index_issue_mismatch_asset_ata_index",
        "perform_final_tx_index_issue_mismatch_recipient_account_index",
        "perform_final_tx_index_issue_mismatch_recipient_ata_index",
        "perform_final_tx_no_token_info",
        "perform_final_tx_mismatch_token_2022",
        "perform_final_tx_mismatch_token_2022_variant",
    ])
    def test_lifi_sign_refused(self, backend, exchange_navigation_helper, fault_test_to_run):
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = SolanaDescriptorTests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = getattr(test_class, fault_test_to_run)
            test_class.run_test("swap_valid_1")
        assert e.value.status == ErrorType.SOLANA_SUMMARY_FINALIZE_FAILED
