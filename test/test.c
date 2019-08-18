#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <freertos/task.h>

#include <wsclient.h>


typedef struct {
  TaskHandle_t wstask;
  wsclient_t *wsclient;
  bool is_received;
} wsclient_test_t;

static wsclient_test_t wstest;

static int onopen(wsclient_t *client, wsclient_test_t *wstest) {
  printf("onopen()\n");
  return 0;
}

static int onmessage(wsclient_t *client, wsclient_message_t *msg, wsclient_test_t *wstest) {
  printf("onmessage(opcode:%04x, len:%zu)\n", msg->opcode, msg->payload_len);
  printf("\t");
  for(size_t i=0; i<msg->payload_len; i++) {
    printf("%02x ", msg->payload[i]);
  }
  printf("\n");
  char *text = (uint8_t *)malloc(msg->payload_len+1);
  memset(text, 0, msg->payload_len+1);
  memcpy(text, msg->payload, msg->payload_len);
  printf("received echo: %s\n", text);
  if(strcmp(text, "hello websocket") == 0) {
    wstest->is_received = true;
  }
  free(text);
  return 0;
}

static int onerror(wsclient_t *client, wsclient_error_t *err, wsclient_test_t *wstest) {
  printf("onerror()\n");
  return 0;
}

static int onclose(wsclient_t *client, wsclient_test_t *wstest) {
  printf("onclose()\n");
  return 0;
}

static void wsclient_main(wsclient_test_t *wstest) {
  wsclient_config_t config;
  config.uri = "wss://echo.websocket.org";
  config.extra_header = NULL;
  config.heart_beat_interval = 10000;
  config.open_cb = (on_open_cb)onopen;
  config.message_cb = (on_message_cb)onmessage;
  config.error_cb = (on_error_cb)onerror;
  config.close_cb = (on_close_cb)onclose;
  config.cbdata = wstest;
  wstest->wsclient = wsclient_new(&config);
  wstest->wsclient->run(wstest->wsclient);
  wstest->wsclient = NULL;
}

void user_init() {
  wstest.is_received = false;
  wstest.wstask = NULL;
  wstest.wsclient = NULL;
  xTaskCreate((TaskFunction_t)wsclient_main, "wsclient task", 1024, (void *)&wstest, 2, &wstest.wstask);
  printf("Waiting websocket connection...\n");
  while(wstest.wsclient == NULL) {
    usleep(1000);
  }
  printf("Connection setup, now send hello and waiting for echo...\n");
  wstest.wsclient->send_text(wstest.wsclient, "hello websocket");
  while(!wstest.is_received) {
    usleep(100*1000);
  }
  printf("Got echo, it works.\n");
  wstest.wsclient->shutdown(wstest.wsclient);
}
