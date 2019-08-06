#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>

#include <check.h>
#include <wsclient.h>

#ifdef _MEMDBG_
#include <memdbg.h>
#endif

typedef struct {
  pthread_t wsthread;
  wsclient_t *wsclient;
  bool is_conn;
  wsclient_message_t recv_msg;
} wsclient_test_t;
static wsclient_test_t wstest;
static void wsclient_main(wsclient_test_t *wstest);

static void wait_and_check_flag(int delaySecs, bool *flag) {
  int delay = 0;
  while(!*flag && delay < delaySecs) {
    usleep(1000*1000);
    delay++;
  }
  ck_assert_int_eq(*flag, 1);
}

static void wait_and_check_flag_x(int delaySecs, bool *flag) {
  int delay = 0;
  while(*flag && delay < delaySecs) {
    usleep(1000*1000);
    delay++;
  }
  ck_assert_int_eq(*flag, 0);
}

static void wait_and_check_cb(int delaySecs, bool (*cb)(void *cbdata), void *cbdata) {
  int delay = 0;
  while((!cb || !cb(cbdata)) && delay < delaySecs) {
    usleep(1000*1000);
    delay++;
  }
  bool flag = (cb ? cb(cbdata) : true);
  ck_assert_int_eq(flag, 1);
}

void test_setup() {
  printf("test_setup()\n");
#ifdef _MEMDBG_
  memdbg_init();
#endif
  wstest.is_conn = false;
  wstest.wsthread = NULL;
  wstest.wsclient = NULL;
  pthread_create(&wstest.wsthread, NULL, (void *(*)(void *))wsclient_main, &wstest);
}

void test_teardown() {
  printf("test_teardown(wsclient=%p)\n", wstest.wsclient);
  if(wstest.is_conn && wstest.wsclient != NULL) {
    wstest.wsclient->shutdown(wstest.wsclient);
    wstest.wsclient = NULL;
  }
  if(wstest.recv_msg.payload != NULL) {
    free(wstest.recv_msg.payload);
  }
  usleep(1000*1000);
#ifdef _MEMDBG_
  memdbg_check();
#endif
}

static int onopen(wsclient_t *client, wsclient_test_t *wstest) {
  printf("onopen()\n");
  wstest->is_conn = true;
  return 0;
}

static int onmessage(wsclient_t *client, wsclient_message_t *msg, wsclient_test_t *wstest) {
  printf("onmessage(opcode:%04x, len:%zu)\n", msg->opcode, msg->payload_len);
  printf("\t");
  for(size_t i=0; i<msg->payload_len; i++) {
    printf("%02x ", msg->payload[i]);
  }
  printf("\n");
  wstest->recv_msg.opcode = msg->opcode;
  wstest->recv_msg.payload_len = msg->payload_len;
  if(wstest->recv_msg.payload != NULL) {
    free(wstest->recv_msg.payload);
  }
  wstest->recv_msg.payload = (uint8_t *)malloc(msg->payload_len);
  memcpy(wstest->recv_msg.payload, msg->payload, msg->payload_len);
  return 0;
}

static int onerror(wsclient_t *client, wsclient_error_t *err, wsclient_test_t *wstest) {
  printf("onerror()\n");
  return 0;
}

static int onclose(wsclient_t *client, wsclient_test_t *wstest) {
  printf("onclose()\n");
  wstest->is_conn = false;
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
  ck_assert_ptr_nonnull(wstest->wsclient);
  wstest->wsclient->run(wstest->wsclient);
  wstest->wsclient = NULL;
}

START_TEST (test_connect)
{
  printf("test_connect(initial is_conn = %d)\n", wstest.is_conn);
  wait_and_check_flag(10, &wstest.is_conn);
}
END_TEST

START_TEST (test_check_socket)
{
  printf("test_check_socket()\n");
  int socket = wstest.wsclient->get_socket(wstest.wsclient);
  ck_assert_int_ne(socket, 0);
}
END_TEST

static bool cmp_received_text_msg(void *cbdata) {
  const char *text = (const char *)cbdata;
  return wstest.recv_msg.opcode == 0x01
    && wstest.recv_msg.payload != NULL
    && strlen(text) == wstest.recv_msg.payload_len
    && memcmp(text, wstest.recv_msg.payload, wstest.recv_msg.payload_len) == 0;
}
START_TEST (test_send_text_msg)
{
  printf("test_send_text_msg()\n");
  const char *text = "Hello web-socket!";
  if(wstest.recv_msg.payload != NULL) {
    free(wstest.recv_msg.payload);
  }
  memset(&wstest.recv_msg, 0, sizeof(wsclient_message_t));
  int n = wstest.wsclient->send_text(wstest.wsclient, text);
  ck_assert_int_eq(n, strlen(text) + 6);
  wait_and_check_cb(10, cmp_received_text_msg, (void *)text);
}
END_TEST

static bool cmp_received_binary_msg(void *cbdata) {
  wsclient_message_t *msg = (wsclient_message_t *)cbdata;
  return wstest.recv_msg.opcode == 0x02
    && wstest.recv_msg.payload != NULL
    && msg->payload_len == wstest.recv_msg.payload_len
    && memcmp(msg->payload, wstest.recv_msg.payload, msg->payload_len) == 0;
}
START_TEST (test_send_binary_msg)
{
  printf("test_send_binary_msg()\n");
  wsclient_message_t msg;
  const uint8_t data[] = {0x46, 0x47, 0x48, 0x49, 0x50, 0x64};
  msg.payload = (uint8_t *)data;
  msg.payload_len = sizeof(data);
  if(wstest.recv_msg.payload != NULL) {
    free(wstest.recv_msg.payload);
  }
  memset(&wstest.recv_msg, 0, sizeof(wsclient_message_t));
  int n = wstest.wsclient->send(wstest.wsclient, data, sizeof(data));
  ck_assert_int_eq(n, sizeof(data) + 6);
  wait_and_check_cb(10, cmp_received_binary_msg, &msg);
}
END_TEST

START_TEST (test_heart_beat)
{
  printf("test_heart_beat()\n");
  wait_and_check_cb(30, NULL, NULL);
}
END_TEST

START_TEST (test_disconnect)
{
  printf("test_disconnect()\n");
  wstest.wsclient->shutdown(wstest.wsclient);
  wait_and_check_flag_x(10, &wstest.is_conn);
}
END_TEST

Suite *create_suite() {
  TCase *tc = tcase_create("websocket client test cases");
  tcase_add_unchecked_fixture(tc, test_setup, test_teardown);
  tcase_add_test(tc, test_connect);
  tcase_add_test(tc, test_check_socket);
  tcase_add_test(tc, test_send_text_msg);
  tcase_add_test(tc, test_send_binary_msg);
  //tcase_add_test(tc, test_heart_beat);
  tcase_add_test(tc, test_disconnect);

  Suite *s = suite_create("websocket client test suite");
  suite_add_tcase(s, tc);
  return s;
}

int main(int argc, const char *argv[]) {
  SRunner *sr;
  Suite *suite;
  int number_failed;
  
  suite = create_suite();
  sr = srunner_create(suite);
  srunner_set_fork_status(sr, CK_NOFORK);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
