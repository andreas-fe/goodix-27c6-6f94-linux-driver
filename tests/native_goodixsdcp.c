/* Exercise native driver state transitions through the actual libfprint API.
 * USB responses and the initial crypto handshake are simulated; actual crypto
 * is independently exercised by test_goodix_native_crypto.py. No USB access.
 */
#define FP_COMPONENT "goodixsdcp"
#include "drivers_api.h"
#include "../driver/goodixsdcp.h"
#include "../driver/goodixsdcp_crypto.h"

static gboolean fake_start (GsdcpSession *, guint8 *);
static gboolean fake_accept (GsdcpSession *, const guint8 *, gsize);
static void fast_jump (FpiSsm *, gint, gint);
#define gsdcp_session_start fake_start
#define gsdcp_session_accept fake_accept
#define fpi_ssm_jump_to_state_delayed fast_jump
#define GSDCP_TEST_TRANSPORT
#include "../driver/goodixsdcp.c"
#undef gsdcp_session_start
#undef gsdcp_session_accept
#undef fpi_ssm_jump_to_state_delayed

typedef enum { SUCCESS, WAIT_RETRY, OVERLAP, BAD_RECONNECT, DUPLICATE,
               REJECT_COMMIT, LOST_COMMIT_REPLY, CHANGE_ORIGINAL,
               CANCEL, WRONG_FIRMWARE, EMPTY_STORE } Scenario;
static Scenario scenario;
static GByteArray *store;
static guint updates, commits, deletions, polls, progress_count, cleanup_count;
static guint8 last_nonce[32];
static GCancellable *test_cancel;

static gboolean
fake_start (GsdcpSession *session, guint8 *hello)
{
  gsdcp_session_clear (session);
  memset (session->key, 'k', 32);
  session->valid = TRUE;
  memset (hello, 0, 162);
  hello[32] = hello[97] = 4;
  return TRUE;
}

static gboolean
fake_accept (GsdcpSession *session, const guint8 *reply, gsize len)
{
  return session->valid && len == 1 && reply[0] == 0;
}

static void
fast_jump (FpiSsm *ssm, gint state, gint delay)
{
  fpi_ssm_jump_to_state (ssm, state);
}

typedef struct {
  FpiDeviceGoodixSdcp *self;
  GoodixCmdCb callback;
  GBytes *reply;
  GError *error;
} Response;

static gboolean
deliver (gpointer user_data)
{
  Response *response = user_data;
  gsize len;
  const guint8 *bytes = g_bytes_get_data (response->reply, &len);
  response->callback (response->self, bytes, len, response->error);
  g_bytes_unref (response->reply);
  g_free (response);
  return G_SOURCE_REMOVE;
}

void
gsdcp_test_command (FpiDeviceGoodixSdcp *self, guint8 command, guint8 subcommand,
                    const guint8 *payload, gsize len, gboolean cancelable, GoodixCmdCb callback)
{
  guint8 reply[2048] = { 0 };
  gsize reply_len = 1;
  GError *error = NULL;
  g_assert_cmpuint (command, !=, 0xc0); /* No configuration writes. */
  switch (command)
    {
    case 0xd0:
      reply_len = 129;
      memcpy (reply + 11, scenario == WRONG_FIRMWARE ? "99999999" : "01010032", 8);
      memcpy (reply + 35, "GF3268", 6);
      break;
    case 0xa6:
      reply_len = store->len;
      memcpy (reply, store->data, reply_len);
      break;
    case 0xe3:
      {
        guint8 plain[512];
        gssize plain_len = gsdcp_decrypt (payload + 4, len - 4, plain, sizeof (plain));
        g_assert_true (plain_len == 162 || plain_len == 32);
        if (subcommand == 2)
          {
            reply_len = 5;
            if (plain_len == 32)
              memcpy (last_nonce, plain, 32);
          }
        else if (subcommand == 1)
          {
            reply_len = 33;
            g_assert_true (gsdcp_session_mac (&self->session, "reconnect", last_nonce, 32, reply + 1));
            if (scenario == BAD_RECONNECT)
              reply[1] ^= 1;
          }
        break;
      }
    case 0xa1:
      reply_len = 33;
      memset (reply + 1, 'n', 32);
      break;
    case 0xa2:
      polls++;
      reply_len = 8;
      reply[1] = 50;
      reply[2] = 100;
      if (scenario == WAIT_RETRY && polls == 1)
        reply[0] = 0xc0;
      break;
    case 0xa0:
      g_assert_cmpuint (len, ==, 3);
      g_assert_cmpuint (payload[0], ==, 1);
      g_assert_cmpuint (payload[1], ==, 100);
      g_assert_cmpuint (payload[2], ==, self->enroll_samples < 5 ? 100 : 80);
      updates++;
      reply_len = 3; /* 000000 must still be credited. */
      if (scenario == OVERLAP && updates == 6)
        reply[0] = 0x72;
      break;
    case 0xa3:
      if (scenario == DUPLICATE)
        reply[0] = 1;
      break;
    case 0xa5:
      reply[0] = 1; /* A new finger in fprintd's enrollment precheck. */
      break;
    case 0xa4:
      {
        commits++;
        g_assert_cmpuint (commits, ==, 1);
        g_assert_cmpuint (self->enroll_samples, ==, 13);
        g_assert_cmpuint (len, ==, GSDCP_RECORD_SIZE);
        if (scenario == REJECT_COMMIT)
          {
            reply[0] = 0x9f;
            break;
          }
        guint8 expected[32];
        guint8 nonce[32];
        memset (nonce, 'n', 32);
        g_assert_true (gsdcp_session_mac (&self->session, "enroll", nonce, 32, expected));
        g_assert_cmpmem (payload + 38, 32, expected, 32);
        guint8 stored[GSDCP_RECORD_SIZE];
        memcpy (stored, payload, GSDCP_RECORD_SIZE);
        memset (stored + 6, 't', 16); /* Sensor-assigned account ID. */
        g_byte_array_append (store, stored, sizeof (stored));
        store->data[1]++;
        if (scenario == CHANGE_ORIGINAL)
          store->data[2 + 75] ^= 1;
        if (scenario == LOST_COMMIT_REPLY)
          error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Lost commit reply");
        break;
      }
    case 0xa7:
      {
        g_assert_cmpint (fpi_device_get_current_action (FP_DEVICE (self)), ==, FPI_DEVICE_ACTION_DELETE);
        g_assert_cmpuint (len, ==, 102);
        g_assert_cmpuint (payload[0], ==, 1);
        g_assert_cmpuint (payload[1], ==, 0);
        deletions++;
        for (guint offset = 2; offset < store->len; offset += 100)
          if (memcmp (store->data + offset + 6, payload + 2 + 6, 16) == 0)
            {
              g_byte_array_remove_range (store, offset, 100);
              store->data[1]--;
              break;
            }
        break;
      }
    case 0xe0:
      if (subcommand == 0)
        cleanup_count++;
      break;
    case 0xe1:
    case 0xb0:
      break;
    default:
      g_assert_not_reached ();
    }
  Response *response = g_new0 (Response, 1);
  response->self = self;
  response->callback = callback;
  response->reply = g_bytes_new (reply, reply_len);
  response->error = error;
  g_idle_add (deliver, response);
}

static void
fake_open (FpDevice *device) { fpi_device_open_complete (device, NULL); }
static void
fake_close (FpDevice *device) { fpi_device_close_complete (device, NULL); }

static void
add_record (guint8 seed)
{
  guint8 record[100] = { 0x62, 0, 0x43, 4, 0xf5, 0 };
  memset (record + 6, seed, 16);
  memset (record + 38, seed + 1, 32);
  record[70] = 28;
  memset (record + 71, seed + 2, 28);
  g_byte_array_append (store, record, sizeof (record));
  store->data[1]++;
}

static FpDevice *
setup_device (Scenario test)
{
  scenario = test;
  updates = commits = deletions = polls = progress_count = cleanup_count = 0;
  store = g_byte_array_new ();
  guint8 count[2] = { 0 };
  g_byte_array_append (store, count, 2);
  if (test != EMPTY_STORE)
    add_record (1);
  FpDeviceClass *klass = g_type_class_ref (fpi_device_goodixsdcp_get_type ());
  klass->type = FP_DEVICE_TYPE_VIRTUAL;
  klass->open = fake_open;
  klass->close = fake_close;
  FpDevice *device = g_object_new (fpi_device_goodixsdcp_get_type (), NULL);
  g_type_class_unref (klass);
  g_autoptr(GError) error = NULL;
  g_assert_true (fp_device_open_sync (device, NULL, &error));
  g_assert_no_error (error);
  return device;
}

static void
progress (FpDevice *dev, gint stage, FpPrint *print, gpointer user_data, GError *error)
{
  if (error)
    return;
  g_assert_cmpint (stage, ==, (gint) ++progress_count);
  if (scenario == CANCEL && stage == 3)
    g_cancellable_cancel (test_cancel);
}

static void
run_enroll (gconstpointer pointer)
{
  Scenario test = GPOINTER_TO_INT (pointer);
  g_autoptr(FpDevice) device = setup_device (test);
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) template = g_object_ref_sink (fp_print_new (device));
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  test_cancel = cancel;
  fp_print_set_finger (template, FP_FINGER_LEFT_INDEX);
  fp_print_set_username (template, "native-test-user");
  g_autoptr(FpPrint) result = fp_device_enroll_sync (device, template, cancel, progress, NULL, &error);
  if (test == SUCCESS || test == WAIT_RETRY || test == OVERLAP || test == LOST_COMMIT_REPLY)
    {
      g_assert_no_error (error);
      g_assert_nonnull (result);
      g_assert_cmpuint (commits, ==, 1);
      g_assert_cmpuint (progress_count, ==, 13);
      guint8 tid[16];
      g_assert_true (print_get_tid (result, tid));
      for (guint i = 0; i < sizeof (tid); i++)
        g_assert_cmpuint (tid[i], ==, 't');
      g_assert_cmpuint (store->data[1], ==, 2);
      g_assert_cmpuint (updates, ==, test == OVERLAP ? 14 : 13);
    }
  else
    {
      g_assert_nonnull (error);
      g_assert_null (result);
      if (test != CHANGE_ORIGINAL && test != REJECT_COMMIT)
        g_assert_cmpuint (commits, ==, 0);
      if (test != CHANGE_ORIGINAL)
        g_assert_cmpuint (store->data[1], ==, test == EMPTY_STORE ? 0 : 1);
    }
  g_assert_cmpuint (deletions, ==, 0);
  g_assert_cmpuint (cleanup_count, ==, 1);
  g_clear_error (&error);
  g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_assert_no_error (error);
  g_byte_array_unref (store);
}

static void
run_delete (void)
{
  g_autoptr(FpDevice) device = setup_device (SUCCESS);
  add_record (9);
  guint8 kept[100];
  memcpy (kept, store->data + 2, 100);
  g_autoptr(FpPrint) requested = g_object_ref_sink (print_from_record (FPI_DEVICE_GOODIXSDCP (device), store->data + 102));
  g_autoptr(GError) error = NULL;
  /* A device-only record is not authorization for automatic cleanup. */
  g_assert_false (fp_device_delete_print_sync (device, requested, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_assert_cmpuint (deletions, ==, 0);
  g_assert_cmpuint (store->len, ==, 202);
  g_clear_error (&error);
  fp_print_set_username (requested, "native-test-user");
  fp_print_set_finger (requested, FP_FINGER_LEFT_INDEX);
  g_assert_true (fp_device_delete_print_sync (device, requested, NULL, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (deletions, ==, 1);
  g_assert_cmpuint (store->len, ==, 102);
  g_assert_cmpmem (store->data + 2, 100, kept, 100);
  /* Repeating an already completed deletion never sends another A7. */
  g_assert_true (fp_device_delete_print_sync (device, requested, NULL, &error));
  g_assert_cmpuint (deletions, ==, 1);
  g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_byte_array_unref (store);
}

static void
run_identify_no_match (void)
{
  g_autoptr(FpDevice) device = setup_device (SUCCESS);
  g_autoptr(GPtrArray) gallery = g_ptr_array_new ();
  g_autoptr(FpPrint) match = NULL;
  g_autoptr(FpPrint) scanned = NULL;
  g_autoptr(GError) error = NULL;
  g_assert_true (fp_device_identify_sync (device, gallery, NULL, NULL, NULL,
                                         &match, &scanned, &error));
  g_assert_no_error (error);
  g_assert_null (match);
  g_assert_null (scanned);
  /* No post-result wait/read: the application can start enrollment now. */
  g_assert_cmpuint (polls, ==, 1);
  g_assert_cmpuint (commits, ==, 0);
  g_assert_cmpuint (store->data[1], ==, 1);
  g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_byte_array_unref (store);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  const gchar *names[] = { "success", "no-finger-retry", "overlap", "bad-reconnect", "duplicate",
                           "rejected-commit", "lost-commit-reply", "changed-original", "cancel",
                           "wrong-firmware", "empty-store" };
  for (guint i = 0; i < G_N_ELEMENTS (names); i++)
    {
      g_autofree gchar *path = g_strdup_printf ("/goodixsdcp/enroll/%s", names[i]);
      g_test_add_data_func (path, GINT_TO_POINTER (i), run_enroll);
    }
  g_test_add_func ("/goodixsdcp/delete/only-requested-record", run_delete);
  g_test_add_func ("/goodixsdcp/identify/no-match-completes-enrollment-precheck", run_identify_no_match);
  return g_test_run ();
}
