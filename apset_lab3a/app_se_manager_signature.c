/***************************************************************************//**
 * @file app_se_manager_signature.c
 * @brief SE manager signature functions.
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

// -----------------------------------------------------------------------------
//                                   Includes
// -----------------------------------------------------------------------------
#include "app_se_manager_signature.h"

// -----------------------------------------------------------------------------
//                              Macros and Typedefs
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                          Static Function Declarations
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Global Variables
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
//                                Static Variables
// -----------------------------------------------------------------------------
/// Command context
static sl_se_command_context_t cmd_ctx;

static  sl_se_custom_weierstrass_prime_domain_t domain_none = {
  .size = 0,
  .p = 0,
  .N = 0,
  .Gx = 0,
  .Gy = 0,
  .a = 0,
  .b = 0,
  .a_is_zero = false,
  .a_is_minus_three = false
};



static sl_se_custom_weierstrass_prime_domain_t *domain= &domain_none;



#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
/// Constants for custom secp256k1 curve
static const uint8_t p_secp256k1[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f };
static const uint8_t N_secp256k1[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                             0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                             0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41 };
static const uint8_t Gx_secp256k1[] = { 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                              0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                              0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
                              0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };
static const uint8_t Gy_secp256k1[] = { 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
                              0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
                              0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
                              0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8 };
static const uint8_t a_secp256k1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t b_secp256k1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07 };

/// Structure for custom ECC curve
static  sl_se_custom_weierstrass_prime_domain_t domain_secp256k1 = {
  .size = DOMAIN_SIZE,
  .p = p_secp256k1,
  .N = N_secp256k1,
  .Gx = Gx_secp256k1,
  .Gy = Gy_secp256k1,
  .a = a_secp256k1,
  .b = b_secp256k1,
  .a_is_zero = true,
  .a_is_minus_three = false
};


/*constants for brainpool224r1
3.3.  Domain Parameters for 224-Bit Curves

   Curve-ID: brainpoolP224r1

      p = D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF

      A = 68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43

      B = 2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B

      x = 0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D

      y = 58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD

      q = D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F

      h = 1
*/

static const uint8_t p_brainpool224r1[] = { 0xD7,0xC1,0x34,0xAA,0x26,0x43,0x66,0x86,
                                  0x2A,0x18,0x30,0x25,0x75,0xD1,0xD7,0x87,
                                  0xB0,0x9F,0x07,0x57,0x97,0xDA,0x89,0xF5,
                                  0x7E,0xC8,0xC0,0xFF};
static const uint8_t a_brainpool224r1[] = { 0x68,0xA5,0xE6,0x2C,0xA9,0xCE,0x6C,0x1C,0x29,0x98,0x03,0xA6,0xC1,0x53,0x0B,0x51,0x4E,0x18,0x2A,0xD8,0xB0,0x04,0x2A,0x59,0xCA,0xD2,0x9F,0x43};
static const uint8_t b_brainpool224r1[] = { 0x25,0x80,0xF6,0x3C,0xCF,0xE4,0x41,0x38,0x87,0x07,0x13,0xB1,0xA9,0x23,0x69,0xE3,0x3E,0x21,0x35,0xD2,0x66,0xDB,0xB3,0x72,0x38,0x6C,0x40,0x0B};
static const uint8_t x_brainpool224r1[] = { 0x0D,0x90,0x29,0xAD,0x2C,0x7E,0x5C,0xF4,0x34,0x08,0x23,0xB2,0xA8,0x7D,0xC6,0x8C,0x9E,0x4C,0xE3,0x17,0x4C,0x1E,0x6E,0xFD,0xEE,0x12,0xC0,0x7D};
static const uint8_t y_brainpool224r1[] = { 0x58,0xAA,0x56,0xF7,0x72,0xC0,0x72,0x6F,0x24,0xC6,0xB8,0x9E,0x4E,0xCD,0xAC,0x24,0x35,0x4B,0x9E,0x99,0xCA,0xA3,0xF6,0xD3,0x76,0x14,0x02,0xCD};
static const uint8_t q_brainpool224r1[] ={ 0xD7,0xC1,0x34,0xAA,0x26,0x43,0x66,0x86,0x2A,0x18,0x30,0x25,0x75,0xD0,0xFB,0x98,0xD1,0x16,0xBC,0x4B,0x6D,0xDE,0xBC,0xA3,0xA5,0xA7,0x93,0x9F};
//     h = 1

static sl_se_custom_weierstrass_prime_domain_t domain_brainpool224r1 = {
  .size = 224/8,
  .p = p_brainpool224r1,
  .N = q_brainpool224r1,
  .Gx = x_brainpool224r1,
  .Gy = y_brainpool224r1,
  .a = a_brainpool224r1,
  .b = b_brainpool224r1,
  .a_is_zero = false,
  .a_is_minus_three = false
};


/* constatns for brainpool512r1
 * 3.7.  Domain Parameters for 512-Bit Curves

   Curve-ID: brainpoolP512r1

      p = AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308
      717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3

      A = 7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863
      BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA

      B = 3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117
      A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723

      x = 81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D009
      8EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822

      y = 7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F81
      11B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892

      q = AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308
      70553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069

      h = 1
 */
static const uint8_t p_brainpool512r1[] = { 0xAA,0xDD,0x9D,0xB8,0xDB,0xE9,0xC4,0x8B,
                              0x3F,0xD4,0xE6,0xAE,0x33,0xC9,0xFC,0x07,
                              0xCB,0x30,0x8D,0xB3,0xB3,0xC9,0xD2,0x0E,
                              0xD6,0x63,0x9C,0xCA,0x70,0x33,0x08,0x71,
                              0x7D,0x4D,0x9B,0x00,0x9B,0xC6,0x68,0x42,
                              0xAE,0xCD,0xA1,0x2A,0xE6,0xA3,0x80,0xE6,
                              0x28,0x81,0xFF,0x2F,0x2D,0x82,0xC6,0x85,
                              0x28,0xAA,0x60,0x56,0x58,0x3A,0x48,0xF3};

static const uint8_t a_brainpool512r1[] = { 0x78,0x30,0xA3,0x31,0x8B,0x60,0x3B,0x89,
                              0xE2,0x32,0x71,0x45,0xAC,0x23,0x4C,0xC5,
                              0x94,0xCB,0xDD,0x8D,0x3D,0xF9,0x16,0x10,
                              0xA8,0x34,0x41,0xCA,0xEA,0x98,0x63,0xBC,
                              0x2D,0xED,0x5D,0x5A,0xA8,0x25,0x3A,0xA1,
                              0x0A,0x2E,0xF1,0xC9,0x8B,0x9A,0xC8,0xB5,
                              0x7F,0x11,0x17,0xA7,0x2B,0xF2,0xC7,0xB9,
                              0xE7,0xC1,0xAC,0x4D,0x77,0xFC,0x94,0xCA};
static const uint8_t b_brainpool512r1[] = { 0x3D,0xF9,0x16,0x10,0xA8,0x34,0x41,0xCA,
                              0xEA,0x98,0x63,0xBC,0x2D,0xED,0x5D,0x5A,
                              0xA8,0x25,0x3A,0xA1,0x0A,0x2E,0xF1,0xC9,
                              0x8B,0x9A,0xC8,0xB5,0x7F,0x11,0x17,0xA7,
                              0x2B,0xF2,0xC7,0xB9,0xE7,0xC1,0xAC,0x4D,
                              0x77,0xFC,0x94,0xCA,0xDC,0x08,0x3E,0x67,
                              0x98,0x40,0x50,0xB7,0x5E,0xBA,0xE5,0xDD,
                              0x28,0x09,0xBD,0x63,0x80,0x16,0xF7,0x23};

static const uint8_t x_brainpool512r1[] = { 0x81,0xAE,0xE4,0xBD,0xD8,0x2E,0xD9,0x64,
                              0x5A,0x21,0x32,0x2E,0x9C,0x4C,0x6A,0x93,
                              0x85,0xED,0x9F,0x70,0xB5,0xD9,0x16,0xC1,
                              0xB4,0x3B,0x62,0xEE,0xF4,0xD0,0x09,0x8E,
                              0xFF,0x3B,0x1F,0x78,0xE2,0xD0,0xD4,0x8D,
                              0x50,0xD1,0x68,0x7B,0x93,0xB9,0x7D,0x5F,
                              0x7C,0x6D,0x50,0x47,0x40,0x6A,0x5E,0x68,
                              0x8B,0x35,0x22,0x09,0xBC,0xB9,0xF8,0x22};
static const uint8_t y_brainpool512r1[] = { 0x7D,0xDE,0x38,0x5D,0x56,0x63,0x32,0xEC,
                              0xC0,0xEA,0xBF,0xA9,0xCF,0x78,0x22,0xFD,
                              0xF2,0x09,0xF7,0x00,0x24,0xA5,0x7B,0x1A,
                              0xA0,0x00,0xC5,0x5B,0x88,0x1F,0x81,0x11,
                              0xB2,0xDC,0xDE,0x49,0x4A,0x5F,0x48,0x5E,
                              0x5B,0xCA,0x4B,0xD8,0x8A,0x27,0x63,0xAE,
                              0xD1,0xCA,0x2B,0x2F,0xA8,0xF0,0x54,0x06,
                              0x78,0xCD,0x1E,0x0F,0x3A,0xD8,0x08,0x92};
static const uint8_t q_brainpool512r1[] = { 0xAA,0xDD,0x9D,0xB8,0xDB,0xE9,0xC4,0x8B,
                              0x3F,0xD4,0xE6,0xAE,0x33,0xC9,0xFC,0x07,
                              0xCB,0x30,0x8D,0xB3,0xB3,0xC9,0xD2,0x0E,
                              0xD6,0x63,0x9C,0xCA,0x70,0x33,0x08,0x70,
                              0x55,0x3E,0x5C,0x41,0x4C,0xA9,0x26,0x19,
                              0x41,0x86,0x61,0x19,0x7F,0xAC,0x10,0x47,
                              0x1D,0xB1,0xD3,0x81,0x08,0x5D,0xDA,0xDD,
                              0xB5,0x87,0x96,0x82,0x9C,0xA9,0x00,0x69};

//      h = 1
static sl_se_custom_weierstrass_prime_domain_t domain_brainpool512r1 = {
  .size = 512/8,
  .p = p_brainpool512r1,
  .N = q_brainpool512r1,
  .Gx = x_brainpool512r1,
  .Gy = y_brainpool512r1,
  .a = a_brainpool512r1,
  .b = b_brainpool512r1,
  .a_is_zero = false,
  .a_is_minus_three = false
};


/// Buffer for asymmetric plain or wrapped key
static uint8_t asymmetric_key_buf[ECC_PRIVKEY_SIZE + ECC_PUBKEY_SIZE + WRAPPED_KEY_OVERHEAD];

/// Buffer for asymmetric custom plain or wrapped key
//#ifndef brainpool512r1
//  static uint8_t asymmetric_custom_key_buf[DOMAIN_SIZE * 6 + DOMAIN_SIZE * 2 + DOMAIN_SIZE + WRAPPED_KEY_OVERHEAD];
//#else
//  static uint8_t asymmetric_custom_key_buf[1024];
//#endif
static uint8_t asymmetric_custom_key_buf[1024];

/// Buffer for asymmetric custom public key
//#ifndef brainpool512r1
//  static uint8_t asymmetric_custom_pubkey_buf[DOMAIN_SIZE * 6 + DOMAIN_SIZE * 2];
//#else
//  static uint8_t asymmetric_custom_pubkey_buf[2024];
//#endif
static uint8_t asymmetric_custom_pubkey_buf[2024];


#else
/// Buffer for asymmetric plain key
static uint8_t asymmetric_key_buf[ECC_PRIVKEY_SIZE + ECC_PUBKEY_SIZE];
#endif

/// Buffer for asymmetric public key
static uint8_t asymmetric_pubkey_buf[ECC_PUBKEY_SIZE];

/// Key descriptor for private key;
static sl_se_key_descriptor_t asymmetric_key_desc;

/// Plain message buffer
static uint8_t plain_msg_buf[PLAIN_MSG_SIZE];

/// Signature buffer
static uint8_t signature_buf[SIGNATURE_SIZE];

/// Plain message length
static size_t plain_msg_len;

// -----------------------------------------------------------------------------
//                          Public Function Definitions
// -----------------------------------------------------------------------------

void set_active_domain(domain_curve_t domain_curve)
{
  switch (domain_curve){
    case DOMAIN_SECP256K1:
      domain = &domain_secp256k1;
      break;
    case DOMAIN_BRAINPOOLP224R1:
      domain = &domain_brainpool224r1;
      break;
    case DOMAIN_BRAINPOOLP512R1:
      domain = &domain_brainpool512r1;
      break;
    default:
      domain = &domain_none;
  }
}


/***************************************************************************//**
 * Get plain message buffer pointer.
 ******************************************************************************/
uint8_t * get_plain_msg_buf_ptr(void)
{
  return(plain_msg_buf);
}

/***************************************************************************//**
 * Set plain message length.
 ******************************************************************************/
void set_plain_msg_len(size_t length)
{
  plain_msg_len = length;
}

/***************************************************************************//**
 * Get the length of the computed signature.
 ******************************************************************************/
size_t get_signature_len(sl_se_key_type_t key_type)
{
  switch (key_type) {
    case SL_SE_KEY_TYPE_ECC_P192:
      return (ECC_P192_PRIVKEY_SIZE * 2);

    case SL_SE_KEY_TYPE_ECC_P256:
      return (ECC_P256_PRIVKEY_SIZE * 2);

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
    case SL_SE_KEY_TYPE_ECC_P384:
      return (ECC_P384_PRIVKEY_SIZE * 2);

    case SL_SE_KEY_TYPE_ECC_P521:
      return (ECC_P521_PRIVKEY_SIZE * 2);

    case SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM:
      //return (DOMAIN_SIZE * 2);
      return domain->size  * 2;

    case SL_SE_KEY_TYPE_ECC_ED25519:
      return (ECC_ED25519_PRIVKEY_SIZE * 2);
#endif

    default:
      return 0;
  }
}

/***************************************************************************//**
 * Initialize the SE Manager.
 ******************************************************************************/
sl_status_t init_se_manager(void)
{
  print_error_cycle(sl_se_init(), NULL);
}

/***************************************************************************//**
 * Deinitialize the SE Manager.
 ******************************************************************************/
sl_status_t deinit_se_manager(void)
{
  print_error_cycle(sl_se_deinit(), NULL);
}

/***************************************************************************//**
 * Generate random numbers and save them to a buffer.
 ******************************************************************************/
sl_status_t generate_random_number(uint8_t *buf, uint32_t size)
{
  print_error_cycle(sl_se_get_random(&cmd_ctx, buf, size), &cmd_ctx);
}

/***************************************************************************//**
 * Generate a plain asymmetric key.
 ******************************************************************************/
sl_status_t create_plain_asymmetric_key(sl_se_key_type_t key_type)
{
  uint32_t req_size;

  // Set up a key descriptor pointing to an external key buffer
  asymmetric_key_desc.type = key_type;
  asymmetric_key_desc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY
                              | SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY
                              | SL_SE_KEY_FLAG_ASYMMMETRIC_SIGNING_ONLY;
  asymmetric_key_desc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT;
  // Set pointer to a RAM buffer to support key generation
  asymmetric_key_desc.storage.location.buffer.pointer = asymmetric_key_buf;
  asymmetric_key_desc.storage.location.buffer.size = sizeof(asymmetric_key_buf);

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
  if (key_type == SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM) {
    asymmetric_key_desc.flags |= SL_SE_KEY_FLAG_ASYMMETRIC_USES_CUSTOM_DOMAIN;
    asymmetric_key_desc.storage.location.buffer.pointer = asymmetric_custom_key_buf;
    asymmetric_key_desc.storage.location.buffer.size = sizeof(asymmetric_custom_key_buf);
    asymmetric_key_desc.domain = domain;
  }
#endif

  if (sl_se_validate_key(&asymmetric_key_desc) != SL_STATUS_OK
      || sl_se_get_storage_size(&asymmetric_key_desc, &req_size) != SL_STATUS_OK
      || asymmetric_key_desc.storage.location.buffer.size < req_size) {
    return SL_STATUS_FAIL;
  }

  print_error_cycle(sl_se_generate_key(&cmd_ctx, &asymmetric_key_desc),
                    &cmd_ctx);
}

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
/***************************************************************************//**
 * Generate a non-exportable wrapped asymmetric key.
 ******************************************************************************/
sl_status_t create_wrap_asymmetric_key(sl_se_key_type_t key_type)
{
  uint32_t req_size;

  // Set up a key descriptor pointing to a wrapped key buffer
  asymmetric_key_desc.type = key_type;
  asymmetric_key_desc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY
                              | SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY
                              | SL_SE_KEY_FLAG_ASYMMMETRIC_SIGNING_ONLY
                              | SL_SE_KEY_FLAG_NON_EXPORTABLE;
  asymmetric_key_desc.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_WRAPPED;
  // Set pointer to a RAM buffer to support key generation
  asymmetric_key_desc.storage.location.buffer.pointer = asymmetric_key_buf;
  asymmetric_key_desc.storage.location.buffer.size = sizeof(asymmetric_key_buf);

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
  if (key_type == SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM) {
    asymmetric_key_desc.flags |= SL_SE_KEY_FLAG_ASYMMETRIC_USES_CUSTOM_DOMAIN;
    asymmetric_key_desc.storage.location.buffer.pointer = asymmetric_custom_key_buf;
    asymmetric_key_desc.storage.location.buffer.size = sizeof(asymmetric_custom_key_buf);
    asymmetric_key_desc.domain = domain;
  }
#endif

  // The size of the wrapped key buffer must have space for the overhead of the
  // key wrapping
  if (sl_se_validate_key(&asymmetric_key_desc) != SL_STATUS_OK
      || sl_se_get_storage_size(&asymmetric_key_desc, &req_size) != SL_STATUS_OK
      || asymmetric_key_desc.storage.location.buffer.size < req_size) {
    return SL_STATUS_FAIL;
  }

  print_error_cycle(sl_se_generate_key(&cmd_ctx, &asymmetric_key_desc),
                    &cmd_ctx);
}

/***************************************************************************//**
 * Generate a non-exportable asymmetric key into a volatile SE key slot.
 ******************************************************************************/
sl_status_t create_volatile_asymmetric_key(sl_se_key_type_t key_type)
{
  // Set up a key descriptor pointing to a volatile SE key slot
  asymmetric_key_desc.type = key_type;
  asymmetric_key_desc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY
                              | SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY
                              | SL_SE_KEY_FLAG_ASYMMMETRIC_SIGNING_ONLY
                              | SL_SE_KEY_FLAG_NON_EXPORTABLE;
  // This key is non-exportable, but can be used from the SE slot
  asymmetric_key_desc.storage.method = SL_SE_KEY_STORAGE_INTERNAL_VOLATILE;
  asymmetric_key_desc.storage.location.slot = ASYMMETRIC_KEY_SLOT;

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
  if (key_type == SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM) {
    asymmetric_key_desc.flags |= SL_SE_KEY_FLAG_ASYMMETRIC_USES_CUSTOM_DOMAIN;
    asymmetric_key_desc.domain = domain;
  }
#endif

  if (sl_se_validate_key(&asymmetric_key_desc) != SL_STATUS_OK) {
    return SL_STATUS_FAIL;
  }

  print_error_cycle(sl_se_generate_key(&cmd_ctx, &asymmetric_key_desc),
                    &cmd_ctx);
}

/***************************************************************************//**
 * Delete a non-exportable asymmetric key in a volatile SE key slot.
 ******************************************************************************/
sl_status_t delete_volatile_asymmetric_key(sl_se_key_type_t key_type)
{
  // Set up a key descriptor pointing to a volatile SE key slot
  asymmetric_key_desc.type = key_type;
  asymmetric_key_desc.flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PRIVATE_KEY
                              | SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY
                              | SL_SE_KEY_FLAG_ASYMMMETRIC_SIGNING_ONLY
                              | SL_SE_KEY_FLAG_NON_EXPORTABLE;
  // This key is non-exportable, but can be used from the SE slot
  asymmetric_key_desc.storage.method = SL_SE_KEY_STORAGE_INTERNAL_VOLATILE;
  asymmetric_key_desc.storage.location.slot = ASYMMETRIC_KEY_SLOT;

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
  if (key_type == SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM) {
    asymmetric_key_desc.flags |= SL_SE_KEY_FLAG_ASYMMETRIC_USES_CUSTOM_DOMAIN;
    asymmetric_key_desc.domain = domain;
  }
#endif

  if (sl_se_validate_key(&asymmetric_key_desc) != SL_STATUS_OK) {
    return SL_STATUS_FAIL;
  }

  print_error_cycle(sl_se_delete_key(&cmd_ctx, &asymmetric_key_desc), &cmd_ctx);
}
#endif

/***************************************************************************//**
 * Export the public key from private key to verify the signature.
 ******************************************************************************/
sl_status_t export_public_key(void)
{
  uint32_t req_size;

  // Set up a key descriptor pointing to an external public key buffer
  sl_se_key_descriptor_t plain_pubkey = {
    .type = asymmetric_key_desc.type,
    .flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY
             | SL_SE_KEY_FLAG_ASYMMMETRIC_SIGNING_ONLY,
    .storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT,
    .storage.location.buffer.pointer = asymmetric_pubkey_buf,
    .storage.location.buffer.size = sizeof(asymmetric_pubkey_buf)
  };

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
  if (plain_pubkey.type == SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM) {
    plain_pubkey.flags |= SL_SE_KEY_FLAG_ASYMMETRIC_USES_CUSTOM_DOMAIN;
    plain_pubkey.storage.location.buffer.pointer = asymmetric_custom_pubkey_buf;
    plain_pubkey.storage.location.buffer.size = sizeof(asymmetric_custom_pubkey_buf);
    plain_pubkey.domain = domain;
  }
#endif

  if (sl_se_validate_key(&plain_pubkey) != SL_STATUS_OK
      || sl_se_get_storage_size(&plain_pubkey, &req_size) != SL_STATUS_OK
      || plain_pubkey.storage.location.buffer.size < req_size) {
    return SL_STATUS_FAIL;
  }

  print_error_cycle(sl_se_export_public_key(&cmd_ctx,
                                            &asymmetric_key_desc,
                                            &plain_pubkey), &cmd_ctx);
}

/***************************************************************************//**
 * Sign the message with private key.
 ******************************************************************************/
sl_status_t sign_message(sl_se_hash_type_t hash_algo)
{
  // Use private key descriptor to sign the message
  print_error_cycle(sl_se_ecc_sign(&cmd_ctx,
                                   &asymmetric_key_desc,
                                   hash_algo,
                                   false,
                                   plain_msg_buf,
                                   plain_msg_len,
                                   signature_buf,
                                   get_signature_len(asymmetric_key_desc.type)),
                    &cmd_ctx);
}

/***************************************************************************//**
 * Verify the signature with public key.
 ******************************************************************************/
sl_status_t verify_signature(sl_se_hash_type_t hash_algo)
{
  uint32_t req_size;

  // Set up a key descriptor pointing to an external public key buffer
  sl_se_key_descriptor_t plain_pubkey = {
    .type = asymmetric_key_desc.type,
    .flags = SL_SE_KEY_FLAG_ASYMMETRIC_BUFFER_HAS_PUBLIC_KEY
             | SL_SE_KEY_FLAG_ASYMMMETRIC_SIGNING_ONLY,
    .storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT,
    .storage.location.buffer.pointer = asymmetric_pubkey_buf,
    .storage.location.buffer.size = sizeof(asymmetric_pubkey_buf)
  };

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
  if (plain_pubkey.type == SL_SE_KEY_TYPE_ECC_WEIERSTRASS_PRIME_CUSTOM) {
    plain_pubkey.flags |= SL_SE_KEY_FLAG_ASYMMETRIC_USES_CUSTOM_DOMAIN;
    plain_pubkey.storage.location.buffer.pointer = asymmetric_custom_pubkey_buf;
    plain_pubkey.storage.location.buffer.size = sizeof(asymmetric_custom_pubkey_buf);
    plain_pubkey.domain = domain;
  }
#endif

  if (sl_se_validate_key(&plain_pubkey) != SL_STATUS_OK
      || sl_se_get_storage_size(&plain_pubkey, &req_size) != SL_STATUS_OK
      || plain_pubkey.storage.location.buffer.size < req_size) {
    return SL_STATUS_FAIL;
  }

  // Use public key descriptor to verify the signature
  print_error_cycle(sl_se_ecc_verify(&cmd_ctx,
                                     &plain_pubkey,
                                     hash_algo,
                                     false,
                                     plain_msg_buf,
                                     plain_msg_len,
                                     signature_buf,
                                     get_signature_len(plain_pubkey.type)),
                    &cmd_ctx);
}

// -----------------------------------------------------------------------------
//                          Static Function Definitions
// -----------------------------------------------------------------------------
