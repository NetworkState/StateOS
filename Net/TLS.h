
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
#include "TLS.h"

constexpr UINT32 CIPHER_EXPANSION_MAX = 256;

enum class EXTENSION_TYPE : UINT16
{
    ext_server_name = 0,                             /* RFC 6066 */
    ext_max_fragment_length = 1,                     /* RFC 6066 */
    ext_status_request = 5,                          /* RFC 6066 */
    ext_supported_groups = 10,                       /* RFC 8422, 7919 */
    ext_ec_point_formats = 11,                       /* RFC 8422 */
    ext_signature_algorithms = 13,                   /* RFC 8446 */
    ext_use_srtp = 14,                               /* RFC 5764 */
    ext_heartbeat = 15,                              /* RFC 6520 */
    ext_application_layer_protocol_negotiation = 16, /* RFC 7301 */
    ext_signed_certificate_timestamp = 18,           /* RFC 6962 */
    ext_client_certificate_type = 19,                /* RFC 7250 */
    ext_server_certificate_type = 20,                /* RFC 7250 */
    ext_padding = 21,                                /* RFC 7685 */
    ext_pre_shared_key = 41,                         /* RFC 8446 */
    ext_early_data = 42,                             /* RFC 8446 */
    ext_supported_versions = 43,                     /* RFC 8446 */
    ext_cookie = 44,                                 /* RFC 8446 */
    ext_psk_key_exchange_modes = 45,                 /* RFC 8446 */
    ext_certificate_authorities = 47,                /* RFC 8446 */
    ext_oid_filters = 48,                            /* RFC 8446 */
    ext_post_handshake_auth = 49,                    /* RFC 8446 */
    ext_signature_algorithms_cert = 50,              /* RFC 8446 */
    ext_key_share = 51,                              /* RFC 8446 */
    ext_quic_transport_parameters = 57,
};
using enum EXTENSION_TYPE;

enum class MESSAGE_TYPE : UINT8
{
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_url = 21,
    certificate_status = 22,
    key_update = 24,
    compressed_certificate = 25,
    message_hash = 254,
    unknown = 255,
};
using enum MESSAGE_TYPE;

enum class QUIC_TRANSPORT_PARAMS : UINT8
{
    original_destination_connection_id = 0,
    max_idle_timeout = 1,
    stateless_reset_token = 2,
    max_udp_payload_size = 3,
    initial_max_data = 4,
    initial_max_stream_data_bidi_local = 5,
    initial_max_stream_data_bidi_remote = 6,
    initial_max_stream_data_uni = 7,
    initial_max_streams_bidi = 8,
    initial_max_streams_uni = 9,
    ack_delay_exponent = 10,
    max_ack_delay = 11,
    disable_active_migration = 12,
    preferred_address = 13,
    active_connection_id_limit = 14,
    initial_source_connection_id = 15,
    retry_source_connection_id = 16,
};
using enum QUIC_TRANSPORT_PARAMS;

enum class RECORD_TYPE : UINT8
{
    record_invalid = 0,
    record_change_cipher_spec = 20,
    record_alert = 21,
    record_handshake = 22,
    record_application_data = 23,
    record_heaart_beat = 24,
};
using enum RECORD_TYPE;

enum class TLS_VERSION : UINT16
{
    VER_TLS10 = 0x0301,
    VER_TLS12 = 0x0303,
    VER_TLS13 = 0x0304,
    VER_DTLS12 = 0xFEFD,
};
using enum TLS_VERSION;

enum class SUPPORTED_GROUPS : UINT16
{
    /* Elliptic Curve Groups (ECDHE) */
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,

    x25519 = 0x001D,
    x448 = 0x001E,

    /* Finite Field Groups (DHE) */
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
};
using enum SUPPORTED_GROUPS;

enum class SIGNATURE_SCHEME : UINT16
{
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,
};
using enum SIGNATURE_SCHEME;

enum class CLIENT_CERTIFICATE_TYPE : UINT8
{
    cert_rsa_sign = 1,
    cert_dss_sign = 2,
    cert_rsa_fixed_dh = 3,
    cert_dss_fixed_dh = 4,
    cert_ecdsa_sign = 64, // RFC4492
    cert_rsa_fixed_ecdh = 65,
    cert_ecdsa_fixed_ecdh = 66,
};
using enum CLIENT_CERTIFICATE_TYPE;

enum class CIPHER_SUITE : UINT16
{
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,

    // for TLS 1.2
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
};
using enum CIPHER_SUITE;

enum class SRTP_PROTECTION_PROFILE : UINT16
{
    SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001,
    SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002,
    SRTP_AEAD_AES_128_GCM = 0x0007,
    SRTP_AEAD_AES_256_GCM = 0x0008,
};
using enum SRTP_PROTECTION_PROFILE;

enum class EC_CURVE_TYPE : UINT8
{
    explicit_prime = 1,
    explicit_char2 = 2,
    named_curve = 3,
};
using enum EC_CURVE_TYPE;

enum class ALERT_LEVEL : UINT8
{
    warning = 1,
    fatal = 2,
};

enum class ALERT_DESCRIPTION : UINT8
{
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};
using enum ALERT_DESCRIPTION;

constexpr UINT32 PRF_HASH_LENGTH = 0x20;
constexpr UINT32 MASTER_SECRET_LENGTH = 0x30;
constexpr UINT32 PRF_RANDOM_LENGTH = 0x20;
constexpr UINT32 PRF_SEED_LENGTH = 0x40;

constexpr UINT32 TLS12_AES_IV_LENGTH = 4;

constexpr UINT32 TLS_DATA_MAX = 16 * 1024;

constexpr UINT32 TLS_RECORD_SIZE = (TLS_DATA_MAX + 256 + 5); // 16K data + 256 bytes for encryption expansion + 5 bytes for record header

constexpr UINT32 TLS_RECORD_HEADER = 5;

