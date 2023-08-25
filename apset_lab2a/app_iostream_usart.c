/***************************************************************************//**
 * @file
 * @brief iostream usart examples functions
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
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "em_chip.h"

#include "sl_iostream.h"
#include "sl_iostream_init_instances.h"
#include "sl_iostream_handles.h"
#include "ml_lab2a.h"

/*******************************************************************************
 *******************************   DEFINES   ***********************************
 ******************************************************************************/

#ifndef BUFSIZE
#define BUFSIZE    80
#endif

#ifndef MSG_SIZE
#define MSG_SIZE 4096
#endif

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

/* Input buffer */
static char buffer[BUFSIZE];

static const uint8_t key[32];
static uint8_t key_size;


static const uint8_t mac[32];
static size_t mac_size;






/*******************************************************************************
 **************************   GLOBAL FUNCTIONS   *******************************
 ******************************************************************************/




/***************************************************************************//**
 * Initialize example.
 ******************************************************************************/
void app_iostream_usart_init(void)
{


  /* Prevent buffering of output/input.*/
#if !defined(__CROSSWORKS_ARM) && defined(__GNUC__)
  setvbuf(stdout, NULL, _IONBF, 0);   /*Set unbuffered mode for stdout (newlib)*/
  setvbuf(stdin, NULL, _IONBF, 0);   /*Set unbuffered mode for stdin (newlib)*/
#endif

  /* Output on vcom usart instance */
  const char str1[] = "IOstream USART example\r\n\r\n";
  sl_iostream_write(sl_iostream_vcom_handle, str1, strlen(str1));

  /* Setting default stream */
  sl_iostream_set_default(sl_iostream_vcom_handle);
  const char str2[] = "This is output on the default stream\r\n";
  sl_iostream_write(SL_IOSTREAM_STDOUT, str2, strlen(str2));

  /* Using printf */
  /* Writing ASCII art to the VCOM iostream */
  printf("Printf uses the default stream, as long as iostream_retarget_stdio is included.\r\n");
}

/***************************************************************************//**
 * Example ticking function.
 ******************************************************************************/
void app_iostream_usart_process_action(void)
{
  int8_t c = 0;
  static uint8_t index = 0;
  static bool print_welcome = true;

  psa_status_t ret;
  psa_key_id_t key_id;
  psa_key_attributes_t key_attr;
  psa_mac_operation_t mac_op;

  ret = psa_crypto_init();

  // Set key attributes



  if (print_welcome) {
    printf("> ");
    print_welcome = false;
  }

  /* Retrieve characters, print local echo and full line back */
  c = getchar();
  if (c > 0) {
    if (c == '\r' || c == '\n') {
      buffer[index] = '\0';


      memset(key,0,sizeof(key));
      memset(mac, 0, sizeof(mac));


      // Create key
      ret = set_cmac_key(key, sizeof(key), &key_id);

      // Get message MAC sign message
      ret = calculate_cmac_message(buffer, index, &key_id, mac, sizeof(mac), &mac_size);


      // Verify MAC
      if(message_cmac_authenticate(key_id, buffer, index, mac, mac_size)){
          printf("\r\nYou wrote: %s\r\n> ", buffer);
      }
      else
        printf("\r\nError: could not verify message authentication.")
      index = 0;
      // Destroy a volatile plain key for HMAC
       ret = psa_destroy_key(key_id);
    } else {
      if (index < BUFSIZE - 1) {
        buffer[index] = c;
        index++;
      }
      /* Local echo */
      putchar(c);
    }
  }
}
