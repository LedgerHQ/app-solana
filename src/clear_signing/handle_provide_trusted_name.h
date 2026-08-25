#pragma once

// PROVIDE TRUSTED NAME (INS 0x29): ingest one signed TRUSTED_NAME descriptor
// into the session cache. Unrelated to the legacy 0x21 handler.
int handle_provide_trusted_name(void);
