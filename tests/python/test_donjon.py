# import pytest
# from solders.pubkey import Pubkey
# from solders.hash import Hash
# from solders.message import Message as MessageSolders
# from solders.transaction import Transaction
# from ragger.utils import RAPDU
# from ragger.error import ExceptionRAPDU

# from .apps.solana import SolanaClient, ErrorType
# from .apps.solana_cmd_builder import verify_signature
# from .apps import solana_utils as SOL
# from spl.token.instructions import TransferCheckedParams, transfer_checked, get_associated_token_address, burn_checked, BurnCheckedParams
# from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID


# CHAIN_ID = 101


# class TestSPLDonjon:
#     def test_send_spl_trusted_name(self, backend, scenario_navigator):
#         # Get the sender public key
#         sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

#         # Get the associated token addresses for the sender
#         sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# # TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
#         destination = str(get_associated_token_address(
#             Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
#             Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
#         ))

#         # Create the transaction
#         transfer_instruction = transfer_checked(
#             TransferCheckedParams(
#                 program_id=TOKEN_PROGRAM_ID,
#                 source=sender_ata,
#                 mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
#                 dest=Pubkey.from_string(destination),
#                 owner=sender_public_key,
#                 amount=1,
#                 decimals=6  # Number of decimals for JUP token
#             )
#         )

#         blockhash = Hash.default()
#         message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
#         tx = Transaction.new_unsigned(message)

#         # Dump the message embedded in the transaction
#         message = tx.message_data()

#         sol = SolanaClient(backend)

#         challenge = sol.get_challenge()


#         sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
#                                  destination.encode('utf-8'),
#                                  SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
#                                  CHAIN_ID,
#                                  challenge=challenge)

#         with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
#             scenario_navigator.review_approve(path=SOL.ROOT_SCREENSHOT_PATH)

#         signature: bytes = sol.get_async_response().data
#         verify_signature(SOL.OWNED_PUBLIC_KEY, message, signature)

#     def test_send_spl_trusted_name_transfer_with_hidden_burn(self, backend, scenario_navigator):
#         # Get the sender public key
#         sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

#         # Get the associated token addresses for the sender
#         sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# # TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
#         destination = str(get_associated_token_address(
#             Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
#             Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
#         ))

#         # Create the transaction
#         transfer_instruction = transfer_checked(
#             TransferCheckedParams(
#                 program_id=TOKEN_PROGRAM_ID,
#                 source=sender_ata,
#                 mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
#                 dest=Pubkey.from_string(destination),
#                 owner=sender_public_key,
#                 amount=1,
#                 decimals=6  # Number of decimals for JUP token
#             )
#         )
#         burn_ins = burn_checked(
#             BurnCheckedParams(
#                 program_id=TOKEN_PROGRAM_ID,
#                 mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
#                 account=sender_ata,
#                 owner=sender_public_key,
#                 amount=10000,
#                 decimals=6,
#             )
#         )

#         blockhash = Hash.default()
#         message = MessageSolders.new_with_blockhash([transfer_instruction, burn_ins], sender_public_key, blockhash)
#         tx = Transaction.new_unsigned(message)

#         # Dump the message embedded in the transaction
#         message = tx.message_data()

#         sol = SolanaClient(backend)

#         challenge = sol.get_challenge()


#         sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
#                                  destination.encode('utf-8'),
#                                  SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
#                                  CHAIN_ID,
#                                  challenge=challenge)

#         with pytest.raises(ExceptionRAPDU) as e:
#             with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
#                 pass
#         assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

#     def test_send_spl_trusted_name_token_2022(self, backend, scenario_navigator):
#         # Get the sender public key
#         sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

#         # Get the associated token addresses for the sender
#         sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# # TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
#         destination = str(get_associated_token_address(
#             Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
#             Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
#         ))

#         # Create the transaction
#         transfer_instruction = transfer_checked(
#             TransferCheckedParams(
#                 program_id=TOKEN_2022_PROGRAM_ID,
#                 source=sender_ata,
#                 mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
#                 dest=Pubkey.from_string(destination),
#                 owner=sender_public_key,
#                 amount=1,
#                 decimals=6  # Number of decimals for JUP token
#             )
#         )

#         blockhash = Hash.default()
#         message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
#         tx = Transaction.new_unsigned(message)

#         # Dump the message embedded in the transaction
#         message = tx.message_data()

#         sol = SolanaClient(backend)

#         challenge = sol.get_challenge()


#         sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
#                                  destination.encode('utf-8'),
#                                  SOL.FOREIGN_ADDRESS_STR.encode('utf-8'),
#                                  CHAIN_ID,
#                                  challenge=challenge)

#         with pytest.raises(ExceptionRAPDU) as e:
#             with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
#                 pass
#         assert e.value.status == ErrorType.SDK_NOT_SUPPORTED

#     def test_send_spl_trusted_name_wrong_ata(self, backend, scenario_navigator):
#         # Get the sender public key
#         sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

#         # Get the associated token addresses for the sender
#         sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# # TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
#         destination = str(get_associated_token_address(
#             Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
#             Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
#         ))

#         # Create the transaction
#         transfer_instruction = transfer_checked(
#             TransferCheckedParams(
#                 program_id=TOKEN_PROGRAM_ID,
#                 source=sender_ata,
#                 mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
#                 dest=Pubkey.from_string(destination),
#                 owner=sender_public_key,
#                 amount=1,
#                 decimals=6  # Number of decimals for JUP token
#             )
#         )

#         blockhash = Hash.default()
#         message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
#         tx = Transaction.new_unsigned(message)

#         # Dump the message embedded in the transaction
#         message = tx.message_data()

#         sol = SolanaClient(backend)

#         challenge = sol.get_challenge()


#         sol.provide_trusted_name(SOL.JUP_MINT_ADDRESS,
#                                  destination.encode('utf-8'),
#                                  SOL.FOREIGN_ADDRESS_STR.replace('A', 'B').encode('utf-8'), # simulation of a compromised backend
#                                  CHAIN_ID,
#                                  challenge=challenge)

#         with pytest.raises(ExceptionRAPDU) as e:
#             with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
#                 pass
#         assert e.value.status == ErrorType.SDK_NOT_SUPPORTED


#     def test_send_spl_no_trusted_name(self, backend, scenario_navigator):
#         # Get the sender public key
#         sender_public_key = Pubkey.from_string(SOL.OWNED_ADDRESS_STR)

#         # Get the associated token addresses for the sender
#         sender_ata = get_associated_token_address(sender_public_key, Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR))
# # TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
#         destination = str(get_associated_token_address(
#             Pubkey.from_string(SOL.FOREIGN_ADDRESS_STR),
#             Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR)
#         ))

#         # Create the transaction
#         transfer_instruction = transfer_checked(
#             TransferCheckedParams(
#                 program_id=TOKEN_PROGRAM_ID,
#                 source=sender_ata,
#                 mint=Pubkey.from_string(SOL.JUP_MINT_ADDRESS_STR),
#                 dest=Pubkey.from_string(destination),
#                 owner=sender_public_key,
#                 amount=1,
#                 decimals=6  # Number of decimals for JUP token
#             )
#         )

#         blockhash = Hash.default()
#         message = MessageSolders.new_with_blockhash([transfer_instruction], sender_public_key, blockhash)
#         tx = Transaction.new_unsigned(message)

#         # Dump the message embedded in the transaction
#         message = tx.message_data()

#         sol = SolanaClient(backend)

#         with pytest.raises(ExceptionRAPDU) as e:
#             with sol.send_async_sign_message(SOL.SOL_PACKED_DERIVATION_PATH, message):
#                 pass
#         assert e.value.status == ErrorType.SDK_NOT_SUPPORTED
