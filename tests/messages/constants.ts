// Mirror of circuits/types/src/messages/constants.nr. Values sourced from
// aztec-packages v4.2.0-nightly.20260408 constants.nr + aztec-nr encoding.nr.
// Keep in sync with the Noir module.

export const PRIVATE_LOG_SIZE_IN_FIELDS = 16;
export const PRIVATE_LOG_CIPHERTEXT_LEN = 15;

export const HEADER_CIPHERTEXT_SIZE_IN_BYTES = 16;
export const AES128_PKCS7_EXPANSION_IN_BYTES = 16;
export const EPH_PK_X_SIZE_IN_FIELDS = 1;
// "Byte budget" per aztec-nr: 402. The actual plaintext truncates to fit
// MESSAGE_PLAINTEXT_LEN whole fields (12), so real plaintext = 12*32 = 384 bytes.
export const MESSAGE_PLAINTEXT_BUDGET_BYTES =
  (PRIVATE_LOG_CIPHERTEXT_LEN - EPH_PK_X_SIZE_IN_FIELDS) * 31
    - HEADER_CIPHERTEXT_SIZE_IN_BYTES
    - AES128_PKCS7_EXPANSION_IN_BYTES; // = 402
export const MESSAGE_PLAINTEXT_LEN = Math.floor(MESSAGE_PLAINTEXT_BUDGET_BYTES / 32); // = 12
export const MESSAGE_PLAINTEXT_SIZE_IN_BYTES = MESSAGE_PLAINTEXT_LEN * 32; // = 384
export const MESSAGE_EXPANDED_METADATA_LEN = 1;
export const MAX_MESSAGE_CONTENT_LEN = MESSAGE_PLAINTEXT_LEN - MESSAGE_EXPANDED_METADATA_LEN;

// Byte space inside the ciphertext after eph_pk.x: 14 * 31 = 434 bytes.
export const CIPHERTEXT_BYTES = (PRIVATE_LOG_CIPHERTEXT_LEN - EPH_PK_X_SIZE_IN_FIELDS) * 31;
// Bytes filled by header + body before zero-pad: 16 + (12*32 + 16) = 416.
export const FILLED_CIPHERTEXT_BYTES = HEADER_CIPHERTEXT_SIZE_IN_BYTES
  + MESSAGE_PLAINTEXT_SIZE_IN_BYTES + AES128_PKCS7_EXPANSION_IN_BYTES;

// Domain separators -- verbatim from upstream constants.nr.
export const DOM_SEP__UNCONSTRAINED_MSG_LOG_TAG = 1485357192;
export const DOM_SEP__PRIVATE_LOG_FIRST_FIELD = 2769976252;
export const DOM_SEP__APP_SILOED_ECDH_SHARED_SECRET = 1707851664;
export const DOM_SEP__ECDH_SUBKEY = 4277646631;
export const DOM_SEP__ECDH_FIELD_MASK = 190532684;
export const DOM_SEP__CONTRACT_ADDRESS_V1 = 1788365517;
export const DOM_SEP__PUBLIC_KEYS_HASH = 777457226;
export const DOM_SEP__NHK_M = 242137788;
export const DOM_SEP__IVSK_M = 2747825907;
export const DOM_SEP__OVSK_M = 4272201051;
export const DOM_SEP__TSK_M = 1546190975;

// L3 namespace (matches L3_MSG_TYPE_NOTE in the Noir module).
export const L3_MSG_TYPE_NOTE = 0x100n;
