#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "psa/crypto.h"


static void print_buffer(uint8_t *array, int array_length);

static void print_key_attributes(psa_key_attributes_t *attributes);
static void clear_terminal_screen();

psa_status_t set_cmac_key(uint8_t* key_buf, size_t key_buf_size);

psa_status_t set_hmac_key(uint8_t* key_buf, size_t key_buf_size);


psa_status_t calculate_cmac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length);
psa_status_t calculate_hmac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length);

bool message_cmac_authenticate(psa_key_id_t key_id, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size);

