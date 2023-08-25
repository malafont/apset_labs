#include "ml_lab2a.h"

static uint8_t key_id;
static psa_key_attributes_t key_attributes;

static uint8_t key[32];
static size_t key_size;
static uint8_t mac[32];
static size_t mac_size;


uint8_t get_mac_key_id(){
  return key_id;
}

psa_key_attributes_t* get_key_attributes_ptr(){
  return &key_attributes;
}


/*
 * Print a non zero terminated buffer values in hex.
 */

void print_buffer(uint8_t *array, int array_length){
  int i;
  for(i=0; i< array_length; i++){
      printf("0x%02X", (unsigned int) (array[i]&0xFF));
      if(i+1 < array_length)
         printf(", ");
  }

}
/*
 * Print the key attributes values.
 */
void print_key_attributes(psa_key_attributes_t *attributes){
  printf("{type: 0x%X, bits: 0X%X, lifetime: 0x%X, id: 0x%X, alg: 0x%X, alg2: 0x%X, usage: 0x%X, flags: 0x%X}",
         attributes->core.type,
         attributes->core.bits,
         (unsigned int)attributes->core.lifetime,
         (unsigned int)attributes->core.id,
         (unsigned int)attributes->core.policy.alg,
         (unsigned int)attributes->core.policy.alg2,
         (unsigned int)attributes->core.policy.usage,
         attributes->core.flags);
}

void clear_terminal_screen(){
  for(int i=0; i<80; i++)
     printf("\n");
}







/****************************************************
 * Set up Attributes and CMAC key.
 ****************************************************/
psa_status_t set_cmac_key(uint8_t* key_buf, size_t key_buf_size){
  psa_key_usage_t flags;
  psa_status_t ret;

  //flags = PSA_KEY_USAGE_SIGN_HASH;
  //flags |= PSA_KEY_USAGE_VERIFY_HASH;
  flags = PSA_KEY_USAGE_SIGN_MESSAGE;
  flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
  //flags |= PSA_KEY_USAGE_DERIVE;

  key_attributes = psa_key_attributes_init();
  psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
  psa_set_key_usage_flags(&key_attributes, flags);
  psa_set_key_algorithm(&key_attributes, PSA_ALG_CMAC);

  // Generate a random key.
  ret = psa_generate_key(&key_attributes, &key_id);
  if(ret == PSA_SUCCESS){
  // Import a volatile plain key
      ret = psa_import_key(&key_attributes, key_buf, key_buf_size, &key_id);
  }
  return ret;

}





/***************************************************
 * Set up Attributes and HMAC key.
 */
psa_status_t set_hmac_key(uint8_t* key_buf, size_t key_buf_size){
  psa_status_t ret;

  key_attributes = psa_key_attributes_init();
  psa_set_key_type(&key_attributes, PSA_KEY_TYPE_HMAC);
  psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
  psa_set_key_algorithm(&key_attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));


  // Generate a random key.
   ret = psa_generate_key(&key_attributes, key_id);
   if(ret == PSA_SUCCESS){
     // Import a volatile plain key for HMAC
     ret = psa_import_key(&key_attributes, key_buf, key_buf_size, key_id);
   }
  return ret;

}

psa_status_t calculate_mac_message(uint8_t* message_buffer,
                                  size_t message_buffer_size,
                                  psa_key_id_t key_id,
                                  psa_algorithm_t alg,
                                  uint8_t* mac_buffer,
                                  size_t mac_buffer_size,
                                  size_t* mac_length){
  psa_status_t ret;
  psa_mac_operation_t mac_op;

  mac_op = psa_mac_operation_init();
  ret = psa_mac_sign_setup(&mac_op, key_id, alg);
  if( ret == PSA_SUCCESS ){
      ret = psa_mac_verify_setup(&mac_op, key_id, alg );
  }
  if (ret == PSA_SUCCESS)
    ret = psa_mac_update(&mac_op, message_buffer, message_buffer_size);
  if (ret == PSA_SUCCESS)
    ret = psa_mac_sign_finish(&mac_op, mac_buffer, mac_buffer_size, mac_length);

  if (ret != PSA_SUCCESS)
    psa_mac_abort(&mac_op);
  return ret;
}


psa_status_t calculate_cmac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length){
  return calculate_mac_message(message_buffer, message_buffer_size, key_id, PSA_ALG_CMAC, mac_buffer, mac_buffer_size, mac_length);
}

psa_status_t calculate_hmac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length){
  return calculate_mac_message(message_buffer, message_buffer_size, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), mac_buffer, mac_buffer_size, mac_length);
}


bool message_cmac_authenticate(psa_key_id_t key_id, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size){
  psa_status_t ret;

  ret = psa_mac_verify(key_id, PSA_ALG_CMAC, message, message_size, mac, mac_size);


  return (ret == PSA_SUCCESS);
}
