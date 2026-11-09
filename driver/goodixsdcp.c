/*
 * Goodix GF3268 SDCP (Windows Hello) fingerprint driver for libfprint
 *
 * Copyright (C) 2026
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define FP_COMPONENT "goodixsdcp"

#include <string.h>

#include "drivers_api.h"
#include "goodixsdcp.h"
#include "goodixsdcp_crypto.h"

/* Endpoints (interface 0): bulk OUT 0x01, bulk IN 0x83. */
#define EP_OUT (0x01 | FPI_USB_ENDPOINT_OUT)
#define EP_IN  (0x03 | FPI_USB_ENDPOINT_IN)
#define EP_IN_BUF 2048

#define USB_INTERFACE 0

#define CMD_TIMEOUT  3000
#define RECV_TIMEOUT 3000
#define FINGER_TIMEOUT 0        /* cancelable long read while waiting for finger */

/* Command bytes. */
#define CMD_POV   0xE1          /* e1 04 */
#define CMD_E3    0xE3          /* SDCP encrypted channel */
#define CMD_PSK   0xE0          /* e0 01 */
#define CMD_CAL   0xB0          /* b0 02 */
#define CMD_ARM   0xA2          /* a2 finger detect / arm */
#define CMD_MATCH 0xA5          /* a5 SDCP match */
#define CMD_LIST  0xA6          /* a6 READ_OTP (template records) */
#define CMD_ACK   0xAA          /* device ACK, skipped */

/* Fixed 162-byte wire ClientHello that brings up the transport channel
 * (from the verified Python reference; the session keys are fixed). */
static const guint8 GSDCP_HELLO[162] = {
  0xf1, 0x57, 0x0b, 0x5c, 0x76, 0xe5, 0x60, 0x9e, 0xcd, 0x6e, 0x94, 0x84, 0x07, 0xc6, 0xed, 0xab,
  0x35, 0xd9, 0xde, 0xde, 0xc6, 0xf6, 0xe4, 0xa5, 0xfb, 0x7a, 0x5a, 0x3a, 0xd4, 0x52, 0xb0, 0x4d,
  0x04, 0x7a, 0x7c, 0xff, 0xa5, 0x40, 0x6c, 0x3b, 0x1d, 0x33, 0x66, 0xef, 0xdb, 0x66, 0xca, 0xf0,
  0xc1, 0xb7, 0xd9, 0x39, 0x5d, 0xef, 0x51, 0xdf, 0x57, 0x26, 0x6f, 0x47, 0x26, 0xce, 0x4a, 0x42,
  0x97, 0x87, 0x1d, 0x51, 0xe3, 0x8f, 0xa8, 0x24, 0xf9, 0x15, 0x6e, 0x8f, 0xda, 0x5d, 0x32, 0x83,
  0x1d, 0x7c, 0x20, 0x56, 0x2d, 0x90, 0x1d, 0x27, 0xe6, 0x0d, 0xdc, 0x16, 0xeb, 0x15, 0x75, 0x2c,
  0x05, 0x04, 0x40, 0x2c, 0x6e, 0x42, 0x27, 0x1d, 0x92, 0xf6, 0xcc, 0xd0, 0xa3, 0xf6, 0x0e, 0x90,
  0x1d, 0xfa, 0x94, 0x7d, 0x19, 0xb6, 0x5b, 0xe8, 0x78, 0xf9, 0x72, 0x3b, 0x33, 0x7f, 0xbc, 0x1c,
  0xd0, 0x49, 0x45, 0x3b, 0xe4, 0x4e, 0x23, 0xa6, 0x1e, 0xba, 0xc0, 0x56, 0x9d, 0x24, 0x87, 0xfb,
  0x81, 0x35, 0x3e, 0x2b, 0x83, 0xd7, 0x22, 0x24, 0x31, 0x4c, 0x5c, 0xf0, 0x2a, 0x7f, 0x40, 0xd9,
  0x01, 0x33,
};

/* Arm payloads. */
static const guint8 ARM_DETECT[4]  = { 0x01, 0x00, 0x23, 0x01 };  /* finger present check */

struct _FpiDeviceGoodixSdcp
{
  FpDevice        parent;
  FpiSsm         *task_ssm;
  FpiSsm         *cmd_ssm;
  FpiUsbTransfer *cmd_transfer;
  gboolean        cmd_cancelable;
  guint8          seq;
  GPtrArray      *list_result;   /* on-chip template records -> FpPrint */

  /* Suspend/resume: our own cancellable for the long "wait for finger" reads,
   * so we can pause the read across a system suspend and re-issue it on resume
   * (without libfprint cancelling the whole verify with "Cannot run while
   * suspended"). Also used for user-initiated cancel. */
  GCancellable   *cancel;
  gboolean        suspended;
  /* Set on resume: the next verify/enroll re-runs the SDCP handshake before
   * arming, because a deep suspend can drop the sensor's transport session. */
  gboolean        need_reinit;
  gboolean        interface_claimed;
  guint           open_retries;
  GsdcpSession    session;
  guint8          enroll_hello[162];
  guint8          enroll_nonce[32];
  guint8          reconnect_nonce[32];
  guint8          enroll_record[GSDCP_RECORD_SIZE];
  GBytes         *enroll_before;
  GError         *enroll_error;
  guint           enroll_samples;
  guint           enroll_attempts;
  guint           enroll_polls;
  guint           enroll_connections;
  guint           enroll_timer;
  gboolean        enroll_timed_out;
  gboolean        enroll_commit_attempted;
  gboolean        enroll_ready;
  GBytes         *delete_before;
  guint8          delete_record[GSDCP_RECORD_SIZE];
  guint           delete_step;
  GError         *delete_error;
};

G_DEFINE_TYPE (FpiDeviceGoodixSdcp, fpi_device_goodixsdcp, FP_TYPE_DEVICE)

typedef void (*GoodixCmdCb) (FpiDeviceGoodixSdcp *self,
                             const guint8 *data, gsize len, GError *error);

typedef struct {
  guint8      cmd0;
  guint8      cmd1;
  GoodixCmdCb callback;
  guint8      rx[4096];
  gsize       rx_len;
} CmdData;

static void
cmd_data_free (CmdData *d) { g_free (d); }

static gboolean
record_valid (const guint8 *record)
{
  return memcmp (record, "\x62\x00\x43\x04", 4) == 0 &&
         record[70] == 28 && record[99] == 0;
}

static gboolean
record_list_valid (const guint8 *data, gsize len)
{
  if (len < 2 || data[0] != 0 || data[1] > 20 ||
      len != 2 + (gsize) data[1] * GSDCP_RECORD_SIZE)
    return FALSE;
  for (guint i = 0; i < data[1]; i++)
    if (!record_valid (data + 2 + i * GSDCP_RECORD_SIZE))
      return FALSE;
  return TRUE;
}

/* ----------------------------------------------------------- FpPrint <-> rec */

/* Pack a 100-byte on-chip template record into an FpPrint's fpi-data. */
static GVariant *
record_to_data (const guint8 *rec)
{
  GVariant *tid, *uid;
  const guint8 *sid;
  gsize sidlen;

  /* record: [6 hdr][16 tid][16 0][32 mac][1 sidlen][28 sid][0] */
  sidlen = rec[70];
  if (sidlen == 0 || sidlen > GSDCP_RECORD_SIZE - 72)
    sidlen = 28;
  sid = rec + 71;

  tid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, rec + 6, GSDCP_TID_SIZE, 1);
  uid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, sid, sidlen, 1);
  return g_variant_new ("(y@ay@ay)", (guint8) 1, tid, uid);
}

/* Store the record data on an existing print (keeps its finger/username). */
static void
apply_record_to_print (FpPrint *print, const guint8 *rec)
{
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", record_to_data (rec), NULL);
}

/* Build a fresh FpPrint from a 100-byte on-chip template record (for list). */
static FpPrint *
print_from_record (FpiDeviceGoodixSdcp *self, const guint8 *rec)
{
  FpPrint *print;
  g_autofree gchar *sidb64 = NULL;
  g_autofree gchar *userid = NULL;
  gsize sidlen;

  sidlen = rec[70];
  if (sidlen == 0 || sidlen > GSDCP_RECORD_SIZE - 72)
    sidlen = 28;

  sidb64 = g_base64_encode (rec + 71, sidlen);
  userid = g_strdup_printf ("GSDCP:%s", sidb64);

  print = fp_print_new (FP_DEVICE (self));
  apply_record_to_print (print, rec);
  g_object_set (print, "description", userid, NULL);
  fpi_print_fill_from_user_id (print, userid);
  return print;
}

/* Extract the 16-byte tid from an FpPrint's fpi-data, or FALSE. */
static gboolean
print_get_tid (FpPrint *print, guint8 tid_out[GSDCP_TID_SIZE])
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) tidv = NULL;
  const guint8 *tid;
  gsize len;
  guint8 finger;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, "(y@ay@ay)", FALSE))
    return FALSE;
  g_variant_get (data, "(y@ay@ay)", &finger, &tidv, NULL);
  tid = g_variant_get_fixed_array (tidv, &len, 1);
  if (len != GSDCP_TID_SIZE)
    return FALSE;
  memcpy (tid_out, tid, GSDCP_TID_SIZE);
  return TRUE;
}

/* ------------------------------------------------------------- command SSM */

static void
cmd_receive_cb (FpiUsbTransfer *transfer, FpDevice *device,
                gpointer user_data, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  CmdData *data = user_data;
  if (self->suspended)
    {
      g_clear_error (&error);
      fpi_device_suspend_complete (device, NULL);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if ((gsize) transfer->actual_length > sizeof (data->rx) - data->rx_len)
    goto malformed;
  memcpy (data->rx + data->rx_len, transfer->buffer, transfer->actual_length);
  data->rx_len += transfer->actual_length;
  while (data->rx_len >= 8)
    {
      gsize field = (gsize) data->rx[4] | ((gsize) data->rx[5] << 8);
      gsize frame_len = 8 + field;
      if (field < 4 || frame_len > sizeof (data->rx))
        goto malformed;
      if (data->rx_len < frame_len)
        break;
      guint8 cmd0, cmd1;
      const guint8 *payload;
      gsize len;
      if (!gsdcp_parse_packet (data->rx, frame_len, &cmd0, &cmd1, NULL, &payload, &len))
        goto malformed;
      if (cmd0 == CMD_ACK)
        {
          if (len < 2 || payload[0] != 0 || payload[1] != data->cmd0)
            goto malformed;
          gsize consumed = (frame_len + 63) & ~((gsize) 63);
          consumed = MIN (consumed, data->rx_len);
          memmove (data->rx, data->rx + consumed, data->rx_len - consumed);
          data->rx_len -= consumed;
          continue;
        }
      if (cmd0 != data->cmd0 || cmd1 != data->cmd1)
        goto malformed;
      GoodixCmdCb callback = data->callback;
      g_autofree guint8 *response = g_memdup2 (payload, len);
      /* Complete the old command before the task callback starts a new one.
       * Copy payload first because completing the SSM releases CmdData. */
      fpi_ssm_mark_completed (transfer->ssm);
      if (callback)
        callback (self, response, len, NULL);
      return;
    }
  fpi_ssm_jump_to_state (transfer->ssm, GSDCP_CMD_RECV);
  return;
malformed:
  fpi_ssm_mark_failed (transfer->ssm,
                       fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                 "Invalid or unexpected Goodix response"));
}

static void
cmd_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  FpiUsbTransfer *transfer;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GSDCP_CMD_SEND:
      self->cmd_transfer->ssm = ssm;
      fpi_usb_transfer_submit (g_steal_pointer (&self->cmd_transfer),
                               CMD_TIMEOUT, NULL,
                               fpi_ssm_usb_transfer_cb, NULL);
      break;

    case GSDCP_CMD_RECV:
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_BUF);
      /* Long "wait for finger" reads use our own cancellable so we can pause
       * them on suspend (and cancel them on user request); short protocol
       * reads are not cancellable. */
      fpi_usb_transfer_submit (transfer,
                               self->cmd_cancelable ? FINGER_TIMEOUT : RECV_TIMEOUT,
                               self->cmd_cancelable ? self->cancel : NULL,
                               cmd_receive_cb, fpi_ssm_get_data (ssm));
      break;
    }
}

static void
cmd_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  CmdData *data = fpi_ssm_get_data (ssm);

  self->cmd_ssm = NULL;
  if (error)
    {
      if (data && data->callback)
        data->callback (self, NULL, 0, error);
      else
        g_error_free (error);
    }
}

/* Send a raw (plaintext) command. Chunks are handled by 64-byte padding. */
static void
goodix_cmd (FpiDeviceGoodixSdcp *self, guint8 cmd0, guint8 cmd1,
            const guint8 *payload, gsize payload_len,
            gboolean cancelable, GoodixCmdCb callback)
{
  g_autoptr(FpiUsbTransfer) transfer = NULL;
  CmdData *data;
  guint8 buf[2048];
  gsize pkt_len;

#ifdef GSDCP_TEST_TRANSPORT
  /* Compile-time test seam; absent from the installed library. */
  extern void gsdcp_test_command (FpiDeviceGoodixSdcp *, guint8, guint8,
                                  const guint8 *, gsize, gboolean, GoodixCmdCb);
  gsdcp_test_command (self, cmd0, cmd1, payload, payload_len, cancelable, callback);
  return;
#endif

  pkt_len = gsdcp_build_package (cmd0, cmd1, self->seq++, payload, payload_len,
                                 buf, sizeof (buf));
  if (pkt_len == 0)
    {
      callback (self, NULL, 0, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Command exceeds packet capacity"));
      return;
    }

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, EP_OUT, pkt_len);
  memcpy (transfer->buffer, buf, pkt_len);

  data = g_new0 (CmdData, 1);
  data->cmd0 = cmd0;
  data->cmd1 = cmd1;
  data->callback = callback;

  self->cmd_transfer = g_steal_pointer (&transfer);
  self->cmd_cancelable = cancelable;
  self->cmd_ssm = fpi_ssm_new (FP_DEVICE (self), cmd_run_state, GSDCP_CMD_NUM_STATES);
  fpi_ssm_set_data (self->cmd_ssm, data, (GDestroyNotify) cmd_data_free);
  fpi_ssm_start (self->cmd_ssm, cmd_ssm_done);
}

/* Send an e3-encrypted command: payload = LE32(inner_len) || inner. */
static void
goodix_cmd_e3 (FpiDeviceGoodixSdcp *self, guint8 cmd1,
               const guint8 *plaintext, gsize pt_len, GoodixCmdCb callback)
{
  guint8 inner[512];
  guint8 payload[520];
  gsize inner_len;

  inner_len = gsdcp_encrypt (plaintext, pt_len, inner, sizeof (inner));
  if (inner_len == 0)
    {
      callback (self, NULL, 0, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Transport encryption failed"));
      return;
    }
  payload[0] = (guint8) (inner_len & 0xFF);
  payload[1] = (guint8) ((inner_len >> 8) & 0xFF);
  payload[2] = (guint8) ((inner_len >> 16) & 0xFF);
  payload[3] = (guint8) ((inner_len >> 24) & 0xFF);
  memcpy (payload + 4, inner, inner_len);
  goodix_cmd (self, CMD_E3, cmd1, payload, 4 + inner_len, FALSE, callback);
}

/* -------------------------------------------------------------- open / init */

static void
init_step_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  if (error)
    {
      /* The first idempotent wake/setup request can time out immediately after
       * system resume. Retry only this request, with a finite budget. Never
       * retry capture/commit or reset the device as an open-recovery action. */
      if (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_OPEN &&
          fpi_ssm_get_cur_state (self->task_ssm) == GSDCP_INIT_POV &&
          g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
          self->open_retries++ < 2)
        {
          fp_dbg ("goodixsdcp: initial setup timed out; retry %u/2", self->open_retries);
          g_clear_error (&error);
          fpi_ssm_jump_to_state_delayed (self->task_ssm, GSDCP_INIT_POV, 300);
          return;
        }
      fp_dbg ("goodixsdcp: handshake step FAILED: %s", error->message);
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  fp_dbg ("goodixsdcp: handshake step ok (%zu bytes)", len);
  fpi_ssm_next_state (self->task_ssm);
}

static void
cache_record_list (FpiDeviceGoodixSdcp *self, const guint8 *data)
{
  g_clear_pointer (&self->list_result, g_ptr_array_unref);
  self->list_result = g_ptr_array_new_with_free_func (g_object_unref);
  for (guint i = 0; i < data[1]; i++)
    g_ptr_array_add (self->list_result,
                     g_object_ref_sink (print_from_record (self, data + 2 + i * GSDCP_RECORD_SIZE)));
}

static void
init_list_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  if (!record_list_valid (data, len))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Unsupported sensor template list"));
      return;
    }
  cache_record_list (self, data);
  fpi_ssm_next_state (self->task_ssm);
}

static void
init_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  guint8 zero = 0x00;
  guint8 b0arg[1] = { 0x00 };

  fp_dbg ("goodixsdcp: init/open handshake state %d", fpi_ssm_get_cur_state (ssm));

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GSDCP_INIT_POV:
      goodix_cmd (self, CMD_POV, 0x04, &zero, 1, FALSE, init_step_cb);
      break;
    case GSDCP_INIT_HELLO2:
      goodix_cmd_e3 (self, 0x02, GSDCP_HELLO, sizeof (GSDCP_HELLO), init_step_cb);
      break;
    case GSDCP_INIT_HELLO0:
      goodix_cmd_e3 (self, 0x00, GSDCP_HELLO, sizeof (GSDCP_HELLO), init_step_cb);
      break;
    case GSDCP_INIT_CAL:
      goodix_cmd (self, CMD_CAL, 0x02, b0arg, 1, FALSE, init_step_cb);
      break;
    case GSDCP_INIT_PSK:
      goodix_cmd (self, CMD_PSK, 0x01, &zero, 1, FALSE, init_step_cb);
      break;
    case GSDCP_INIT_LIST:
      goodix_cmd (self, CMD_LIST, 0x00, &zero, 1, FALSE, init_list_cb);
      break;
    }
}

static void
open_complete (FpDevice *dev, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);

  /* libfprint opens GUsb before invoking dev_open, but this baseline does not
   * close it when driver initialization fails. Unwind both ownership levels
   * here, otherwise every later claim fails with GUsb's "already open". */
  if (error)
    {
      GUsbDevice *usb = fpi_device_get_usb_device (dev);
      if (self->interface_claimed)
        {
          g_usb_device_release_interface (usb, USB_INTERFACE, 0, NULL);
          self->interface_claimed = FALSE;
        }
      g_usb_device_close (usb, NULL);
      self->suspended = FALSE;
      self->need_reinit = FALSE;
      g_clear_object (&self->cancel);
    }
  self->task_ssm = NULL;
  fpi_device_open_complete (dev, error);
}

static void
init_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  open_complete (dev, error);
}

static void
dev_open (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (device);

  fp_dbg ("goodixsdcp: dev_open (claim iface %d)", USB_INTERFACE);

  self->suspended = FALSE;
  self->need_reinit = FALSE;
  self->open_retries = 0;
  if (!g_usb_device_claim_interface (usb, USB_INTERFACE, 0, &error))
    {
      fp_dbg ("goodixsdcp: dev_open claim FAILED: %s",
              error ? error->message : "?");
      open_complete (device, error);
      return;
    }
  self->interface_claimed = TRUE;
  self->seq = 0;
  self->task_ssm = fpi_ssm_new (device, init_run_state, GSDCP_INIT_NUM_STATES);
  fpi_ssm_start (self->task_ssm, init_ssm_done);
}

static void
close_cleanup_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  FpDevice *device = FP_DEVICE (self);
  GError *release_error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  if (!error && (!len || data[0] != 0))
    error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Cannot disable fingerprint power-button shield");
  g_usb_device_release_interface (usb, USB_INTERFACE, 0, &release_error);
  self->interface_claimed = FALSE;
  if (!error)
    error = release_error;
  else
    g_clear_error (&release_error);
  g_clear_object (&self->cancel);
  fpi_device_close_complete (device, error);
}

static void
dev_close (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  guint8 zero = 0;
  goodix_cmd (self, CMD_PSK, 0, &zero, 1, FALSE, close_cleanup_cb);
}

/* ------------------------------------------------------- verify / identify */

/* TRUE if both prints carry the same on-chip template id. */
static gboolean
print_tid_equal (FpPrint *a, FpPrint *b)
{
  guint8 ta[GSDCP_TID_SIZE], tb[GSDCP_TID_SIZE];

  if (!print_get_tid (a, ta) || !print_get_tid (b, tb))
    return FALSE;
  return memcmp (ta, tb, GSDCP_TID_SIZE) == 0;
}

/* Report a match result, then finish the task. new_scan is transferred. */
static void
report_match (FpiDeviceGoodixSdcp *self, FpPrint *new_scan)
{
  FpDevice *dev = FP_DEVICE (self);
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  FpPrint *matching = NULL;

  if (new_scan)
    {
      if (action == FPI_DEVICE_ACTION_VERIFY)
        {
          FpPrint *req = NULL;
          fpi_device_get_verify_data (dev, &req);
          if (req && print_tid_equal (req, new_scan))
            matching = req;
        }
      else /* IDENTIFY */
        {
          GPtrArray *gallery = NULL;
          fpi_device_get_identify_data (dev, &gallery);
          for (guint i = 0; gallery && i < gallery->len; i++)
            {
              FpPrint *p = g_ptr_array_index (gallery, i);
              if (print_tid_equal (p, new_scan))
                {
                  matching = p;
                  break;
                }
            }
        }
    }

  if (action == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_report (dev, matching ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                              new_scan, NULL);
  else
    fpi_device_identify_report (dev, matching, new_scan, NULL);
}

static void
verify_match_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  FpPrint *new_scan = NULL;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                           FP_FINGER_STATUS_PRESENT,
                                           FP_FINGER_STATUS_NONE);

  fp_dbg ("a5 verify response: %zu bytes, first=%02x", len, len ? data[0] : 0);

  if (len >= GSDCP_RECORD_SIZE + 8 && data[0] == 0 && record_valid (data + 8))
    {
      /* match token: matched record embedded at offset 8.
       * report_match() hands new_scan to fpi_device_*_report (transfer full),
       * so we must NOT unref it afterwards. */
      new_scan = print_from_record (self, data + 8);
      report_match (self, new_scan);
      fpi_ssm_mark_completed (self->task_ssm);
    }
  else if (len >= 1 && data[0] == 0x01)
    {
      /* A no-match is a completed identify result. In particular, fprintd's
       * enrollment precheck must finish here before starting native capture.
       * A second sensor read could time out and report the same result twice. */
      report_match (self, NULL);
      fpi_ssm_mark_completed (self->task_ssm);
    }
  else
    {
      /* no clean finger read: ask to retry */
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
    }
}


static void
verify_arm_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  /* a2 returns finger region on contact, 0xc0.. when no finger */
  if (len >= 1 && data[0] == 0xc0)
    {
      fpi_ssm_jump_to_state (self->task_ssm, GSDCP_VER_ARM);   /* wait for finger */
      return;
    }
  fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                           FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_PRESENT);
  fpi_ssm_next_state (self->task_ssm);
}

/* Optional session-refresh prefix shared by verify and enroll. Runs the SDCP
 * handshake (POV/HELLO/CAL/PSK) again before arming, but only when
 * self->need_reinit is set (after a resume). Returns TRUE if the current state
 * was a reinit state and has been handled here. Reuses init_step_cb, which
 * advances self->task_ssm (== the running verify/enroll SSM) on success. */
static gboolean
gsdcp_reinit_state (FpiDeviceGoodixSdcp *self, FpiSsm *ssm)
{
  guint8 zero = 0x00;
  guint8 b0arg[1] = { 0x00 };

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GSDCP_VER_REINIT_POV:
      if (!self->need_reinit)
        {
          /* normal start: no session refresh needed */
          fpi_ssm_jump_to_state (ssm, GSDCP_VER_ARM);
          return TRUE;
        }
      fp_dbg ("goodixsdcp: resume session-refresh: re-running SDCP handshake");
      goodix_cmd (self, CMD_POV, 0x04, &zero, 1, FALSE, init_step_cb);
      return TRUE;
    case GSDCP_VER_REINIT_HELLO2:
      goodix_cmd_e3 (self, 0x02, GSDCP_HELLO, sizeof (GSDCP_HELLO), init_step_cb);
      return TRUE;
    case GSDCP_VER_REINIT_HELLO0:
      goodix_cmd_e3 (self, 0x00, GSDCP_HELLO, sizeof (GSDCP_HELLO), init_step_cb);
      return TRUE;
    case GSDCP_VER_REINIT_CAL:
      goodix_cmd (self, CMD_CAL, 0x02, b0arg, 1, FALSE, init_step_cb);
      return TRUE;
    case GSDCP_VER_REINIT_PSK:
      self->need_reinit = FALSE;   /* refresh complete; -> GSDCP_VER_ARM next */
      goodix_cmd (self, CMD_PSK, 0x01, &zero, 1, FALSE, init_step_cb);
      return TRUE;
    default:
      return FALSE;
    }
}

static void
verify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  guint8 nonce[32];

  if (gsdcp_reinit_state (self, ssm))
    return;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GSDCP_VER_ARM:
      fp_dbg ("goodixsdcp: verify: arming (a2), waiting for finger");
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_NONE);
      goodix_cmd (self, CMD_ARM, 0x00, ARM_DETECT, sizeof (ARM_DETECT), TRUE, verify_arm_cb);
      break;
    case GSDCP_VER_MATCH:
      /* a5 with a fresh 32-byte value (content not validated by the sensor) */
      for (int i = 0; i < 32; i++)
        nonce[i] = (guint8) g_random_int_range (0, 256);
      goodix_cmd (self, CMD_MATCH, 0x00, nonce, sizeof (nonce), TRUE, verify_match_cb);
      break;
    }
}

static void
verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);

  self->task_ssm = NULL;
  if (error)
    {
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, g_error_copy (error));
      else
        fpi_device_identify_report (dev, NULL, NULL, g_error_copy (error));
      /* Retry errors belong to the report callback, never the complete API. */
      if (error->domain == FP_DEVICE_RETRY)
        g_clear_error (&error);
    }
  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);
}

static void
dev_verify_identify (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);

  self->suspended = FALSE;
  self->need_reinit = FALSE;
  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY &&
      self->list_result && self->list_result->len == 0)
    {
      /* Fresh A6 during open confirmed an empty sensor. No stored finger can
       * match; A5 on this firmware returns 03 in that state. Do not turn this
       * enrollment precheck into an unnecessary finger acquisition/error. */
      fp_dbg ("goodixsdcp: identify precheck: sensor list is empty, no match");
      fpi_device_identify_report (device, NULL, NULL, NULL);
      fpi_device_identify_complete (device, NULL);
      return;
    }

  self->task_ssm = fpi_ssm_new (device, verify_run_state, GSDCP_VER_NUM_STATES);
  fpi_ssm_start (self->task_ssm, verify_ssm_done);
}

/* --------------------------------------------------------- native enroll */

/* A fresh local SID-shaped identity, not a Windows credential.
 * This tests an emptied, previously provisioned sensor, not a factory reset.
 * No old record, cached SID, host reference or vendor configuration is read. */
static gboolean
prepare_empty_identity (guint8 record[GSDCP_RECORD_SIZE])
{
  static const guint8 header[] = { 0x62, 0, 0x43, 4, 0xf5, 0 };
  static const guint8 sid_prefix[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0 };
  memset (record, 0, GSDCP_RECORD_SIZE);
  memcpy (record, header, sizeof (header));
  record[70] = 28;
  memcpy (record + 71, sid_prefix, sizeof (sid_prefix));
  if (!gsdcp_random (record + 83, 12))
    return FALSE;
  /* S-1-5-21-<three random subauthorities>-1000, little-endian RID. */
  record[95] = 0xe8;
  record[96] = 3;
  return TRUE;
}

static void
enroll_abort (FpiDeviceGoodixSdcp *self, GError *error)
{
  gint state = fpi_ssm_get_cur_state (self->task_ssm);
  if (!self->enroll_error)
    self->enroll_error = error;
  else
    g_clear_error (&error);
  if (state == GSDCP_EN_OFF)
    fpi_ssm_mark_completed (self->task_ssm);
  else
    fpi_ssm_jump_to_state (self->task_ssm,
                           self->enroll_commit_attempted && state < GSDCP_EN_POST_LIST ?
                           GSDCP_EN_POST_LIST : GSDCP_EN_OFF);
}

static gboolean
records_preserved (const guint8 *before, gsize before_len,
                   const guint8 *after, gsize after_len,
                   const guint8 *removed)
{
  for (gsize i = 2; i + GSDCP_RECORD_SIZE <= before_len; i += GSDCP_RECORD_SIZE)
    {
      if (removed && memcmp (before + i, removed, GSDCP_RECORD_SIZE) == 0)
        continue;
      gboolean found = FALSE;
      for (gsize j = 2; j + GSDCP_RECORD_SIZE <= after_len; j += GSDCP_RECORD_SIZE)
        if (memcmp (before + i, after + j, GSDCP_RECORD_SIZE) == 0)
          found = TRUE;
      if (!found)
        return FALSE;
    }
  return TRUE;
}

static void
enroll_step_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  gint state = fpi_ssm_get_cur_state (self->task_ssm);
  if (error)
    {
      enroll_abort (self, error);
      return;
    }
  if (state == GSDCP_EN_VERSION)
    {
      if (len != 129 || data[0] != 0 || memcmp (data + 11, "01010032", 8) != 0 ||
          memcmp (data + 35, "GF3268", 6) != 0)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                         "Native enrollment requires GF3268 firmware 01010032"));
          return;
        }
    }
  else if (state == GSDCP_EN_LIST)
    {
      if (!record_list_valid (data, len))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Invalid enrollment template list"));
          return;
        }
      if (data[1] == 20)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_FULL, "Fingerprint storage is full"));
          return;
        }
      if (data[1] == 0)
        {
          if (!prepare_empty_identity (self->enroll_record))
            {
              enroll_abort (self, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
              return;
            }
          fp_info ("goodixsdcp: empty template store: fresh local identity, no prior-record metadata");
        }
      else
        memcpy (self->enroll_record, data + 2, GSDCP_RECORD_SIZE);
      self->enroll_before = g_bytes_new (data, len);
    }
  else if (state == GSDCP_EN_POST_LIST)
    {
      gsize before_len = 0;
      const guint8 *before = self->enroll_before ? g_bytes_get_data (self->enroll_before, &before_len) : NULL;
      if (!record_list_valid (data, len) || !before || len != before_len + GSDCP_RECORD_SIZE ||
          !records_preserved (before, before_len, data, len, NULL))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                         "Enrollment readback did not confirm one additional template and unchanged originals"));
          return;
        }
      const guint8 *created = NULL;
      guint found = 0;
      for (guint i = 0; i < data[1]; i++)
        {
          const guint8 *record = data + 2 + i * GSDCP_RECORD_SIZE;
          if (memcmp (record + 38, self->enroll_record + 38, 32) == 0)
            {
              created = record;
              found++;
            }
        }
      if (found != 1)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                         "Stored template does not have the expected enrollment identifier"));
          return;
        }
      /* Use the sensor-assigned account ID, not the prepared random bytes. */
      FpPrint *print = NULL;
      fpi_device_get_enroll_data (dev, &print);
      apply_record_to_print (print, created);
      cache_record_list (self, data);
      self->enroll_ready = TRUE;
      /* Readback can confirm a commit even if its response was lost. */
      g_clear_error (&self->enroll_error);
    }
  else if (state == GSDCP_EN_HELLO0)
    {
      if (!gsdcp_session_accept (&self->session, data, len))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "SDCP server authentication failed"));
          return;
        }
      if (++self->enroll_connections < 2)
        {
          fpi_ssm_jump_to_state (self->task_ssm, GSDCP_EN_POV);
          return;
        }
    }
  else if (state == GSDCP_EN_RECONNECT1)
    {
      if (!gsdcp_session_check_reconnect (&self->session, self->reconnect_nonce, data, len))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "SDCP reconnect authentication failed"));
          return;
        }
    }
  else if (state == GSDCP_EN_ARM)
    {
      if (len && (data[0] == 0xc0 || data[0] == 0x71 || data[0] == 0x72 || data[0] == 0x73))
        {
          fpi_ssm_jump_to_state_delayed (self->task_ssm, GSDCP_EN_RECONNECT2, 200);
          return;
        }
      if (len < 3 || data[0] != 0)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Invalid fingerprint capture response"));
          return;
        }
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT, FP_FINGER_STATUS_NEEDED);
      if (data[1] < 15 || data[2] < 65)
        {
          fpi_device_enroll_progress (dev, self->enroll_samples, NULL,
                                      fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          fpi_ssm_jump_to_state_delayed (self->task_ssm, GSDCP_EN_RECONNECT2, 1200);
          return;
        }
    }
  else if (state == GSDCP_EN_UPDATE)
    {
      if (len == 3 && (data[0] == 0x72 || data[0] == 0x73))
        {
          fpi_device_enroll_progress (dev, self->enroll_samples, NULL,
                                      fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
          fpi_ssm_jump_to_state_delayed (self->task_ssm, GSDCP_EN_RECONNECT2, 1200);
          return;
        }
      if (len != 3 || data[0] != 0)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                         "Sensor rejected enrollment update (0x%02x)", len ? data[0] : 0xff));
          return;
        }
      self->enroll_samples++;
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_PRESENT);
      fpi_device_enroll_progress (dev, self->enroll_samples, NULL, NULL);
      fpi_ssm_jump_to_state_delayed (self->task_ssm,
                                     self->enroll_samples == 13 ? GSDCP_EN_DUPLICATE : GSDCP_EN_RECONNECT2,
                                     self->enroll_samples == 13 ? 0 : 1200);
      return;
    }
  else if (state == GSDCP_EN_DUPLICATE)
    {
      if (len != 1 || data[0] != 0)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_DUPLICATE,
                         "This finger is already stored on the sensor"));
          return;
        }
    }
  else if (state == GSDCP_EN_BEGIN)
    {
      if (len != 33 || data[0] != 0)
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Invalid enrollment nonce"));
          return;
        }
      memcpy (self->enroll_nonce, data + 1, 32);
    }
  else
    {
      if (!len || data[0] != 0 ||
          ((state == GSDCP_EN_HELLO2 || state == GSDCP_EN_RECONNECT2) && len != 5))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                         "Enrollment command failed in state %d (0x%02x)", state, len ? data[0] : 0xff));
          return;
        }
    }
  if (state == GSDCP_EN_OFF)
    fpi_ssm_mark_completed (self->task_ssm);
  else
    fpi_ssm_next_state (self->task_ssm);
}

static void
enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  guint8 zero = 0;
  gint state = fpi_ssm_get_cur_state (ssm);
  if (state < GSDCP_EN_POST_LIST && g_cancellable_is_cancelled (self->cancel))
    {
      enroll_abort (self, self->enroll_timed_out ?
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Fingerprint enrollment timed out") :
                     g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint enrollment cancelled"));
      return;
    }
  switch (state)
    {
    case GSDCP_EN_VERSION:
      goodix_cmd (self, 0xd0, 0, &zero, 1, FALSE, enroll_step_cb);
      break;
    case GSDCP_EN_LIST:
    case GSDCP_EN_POST_LIST:
      goodix_cmd (self, CMD_LIST, 0, &zero, 1, FALSE, enroll_step_cb);
      break;
    case GSDCP_EN_POV:
      if (!gsdcp_session_start (&self->session, self->enroll_hello))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Cannot create a fresh SDCP connection"));
          break;
        }
      goodix_cmd (self, CMD_POV, 4, &zero, 1, FALSE, enroll_step_cb);
      break;
    case GSDCP_EN_HELLO2:
    case GSDCP_EN_HELLO0:
      goodix_cmd_e3 (self, state == GSDCP_EN_HELLO2 ? 2 : 0,
                      self->enroll_hello, sizeof (self->enroll_hello), enroll_step_cb);
      break;
    case GSDCP_EN_CAL:
    case GSDCP_EN_SAMPLE_CAL:
      goodix_cmd (self, CMD_CAL, 2, &zero, 1, FALSE, enroll_step_cb);
      break;
    case GSDCP_EN_SHIELD:
    case GSDCP_EN_OFF:
      goodix_cmd (self, CMD_PSK, state == GSDCP_EN_SHIELD ? 1 : 0, &zero, 1, FALSE, enroll_step_cb);
      break;
    case GSDCP_EN_BEGIN:
    case GSDCP_EN_DUPLICATE:
      goodix_cmd (self, state == GSDCP_EN_BEGIN ? 0xa1 : 0xa3, 0, &zero, 1, FALSE, enroll_step_cb);
      break;
    case GSDCP_EN_RECONNECT2:
      if (!gsdcp_random (self->reconnect_nonce, 32))
        {
          enroll_abort (self, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          break;
        }
      goodix_cmd_e3 (self, 2, self->reconnect_nonce, 32, enroll_step_cb);
      break;
    case GSDCP_EN_RECONNECT1:
      goodix_cmd_e3 (self, 1, self->reconnect_nonce, 32, enroll_step_cb);
      break;
    case GSDCP_EN_ARM:
      {
        const guint8 capture[] = { 0, 0x0f, 0x41, 1 };
        if (++self->enroll_polls > 90)
          {
            enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Enrollment retry limit reached"));
            break;
          }
        fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NEEDED, FP_FINGER_STATUS_PRESENT);
        goodix_cmd (self, CMD_ARM, 0, capture, sizeof (capture), TRUE, enroll_step_cb);
        break;
      }
    case GSDCP_EN_UPDATE:
      {
        const guint8 update[] = { 1, 100, self->enroll_samples < 5 ? 100 : 80 };
        if (++self->enroll_attempts > 39)
          {
            enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Too many overlapping enrollment samples"));
            break;
          }
        goodix_cmd (self, 0xa0, 0, update, sizeof (update), FALSE, enroll_step_cb);
        break;
      }
    case GSDCP_EN_COMMIT:
      if (self->enroll_samples != 13 || self->enroll_commit_attempted ||
          !gsdcp_session_mac (&self->session, "enroll", self->enroll_nonce, 32, self->enroll_record + 38) ||
          !gsdcp_random (self->enroll_record + 6, 16))
        {
          enroll_abort (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Invalid enrollment commit state"));
          break;
        }
      self->enroll_record[5] = 0;
      memset (self->enroll_record + 22, 0, 16);
      /* A4 is consumed BEFORE submission: never retry an uncertain write. */
      self->enroll_commit_attempted = TRUE;
      goodix_cmd (self, 0xa4, 0, self->enroll_record, GSDCP_RECORD_SIZE, FALSE, enroll_step_cb);
      break;
    }
}

static gboolean
enroll_timeout_cb (gpointer user_data)
{
  FpiDeviceGoodixSdcp *self = user_data;
  self->enroll_timer = 0;
  self->enroll_timed_out = TRUE;
  g_cancellable_cancel (self->cancel);
  return G_SOURCE_REMOVE;
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  FpPrint *print = NULL;
  self->task_ssm = NULL;
  if (self->enroll_timer)
    {
      g_source_remove (self->enroll_timer);
      self->enroll_timer = 0;
    }
  if (!error)
    error = g_steal_pointer (&self->enroll_error);
  else
    g_clear_error (&self->enroll_error);
  if (!error && !self->enroll_ready)
    error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Enrollment did not produce a verified stored template");
  if (!error)
    fpi_device_get_enroll_data (dev, &print);
  gsdcp_session_clear (&self->session);
  OPENSSL_cleanse (self->enroll_nonce, sizeof (self->enroll_nonce));
  g_clear_pointer (&self->enroll_before, g_bytes_unref);
  fpi_device_enroll_complete (dev, print ? g_object_ref (print) : NULL, error);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  self->suspended = FALSE;
  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();
  g_clear_error (&self->enroll_error);
  g_clear_pointer (&self->enroll_before, g_bytes_unref);
  self->enroll_samples = self->enroll_attempts = self->enroll_polls = self->enroll_connections = 0;
  self->enroll_ready = self->enroll_commit_attempted = self->enroll_timed_out = FALSE;
  self->enroll_timer = g_timeout_add_seconds (180, enroll_timeout_cb, self);
  self->task_ssm = fpi_ssm_new (device, enroll_run_state, GSDCP_EN_NUM_STATES);
  fpi_ssm_start (self->task_ssm, enroll_ssm_done);
}


/* -------------------------------------------------------------- list */

static void
dev_list (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  GPtrArray *result;

  result = g_ptr_array_new_with_free_func (g_object_unref);
  if (self->list_result)
    {
      for (guint i = 0; i < self->list_result->len; i++)
        g_ptr_array_add (result, g_object_ref (g_ptr_array_index (self->list_result, i)));
    }
  fpi_device_list_complete (device, result, NULL);
}

/* -------------------------------------------------------------- delete */

static void
delete_finish (FpiDeviceGoodixSdcp *self, GError *error)
{
  g_clear_pointer (&self->delete_before, g_bytes_unref);
  g_clear_error (&self->delete_error);
  fpi_device_delete_complete (FP_DEVICE (self), error);
}

static void
delete_step_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  FpDevice *device = FP_DEVICE (self);
  guint8 zero = 0;
  if (self->delete_step == 1)
    {
      /* Never repeat A7, even when its response was lost. Query the result. */
      if (error)
        self->delete_error = error;
      else if (len != 1 || data[0] != 0)
        self->delete_error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Sensor rejected fingerprint deletion");
      self->delete_step = 2;
      goodix_cmd (self, CMD_LIST, 0, &zero, 1, FALSE, delete_step_cb);
      return;
    }
  if (error || !record_list_valid (data, len))
    {
      delete_finish (self, error ? error :
                      fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Invalid deletion template list"));
      return;
    }
  if (self->delete_step == 0)
    {
      FpPrint *print = NULL;
      guint8 tid[GSDCP_TID_SIZE];
      fpi_device_get_delete_data (device, &print);
      /* fprintd may try to garbage-collect unclaimed device records when full
       * or during duplicate prechecks. Those may belong to Windows. Only a
       * concrete host reference with user/finger metadata authorizes deletion. */
      if (print && (!fp_print_get_username (print) || !*fp_print_get_username (print) ||
                    fp_print_get_finger (print) == FP_FINGER_UNKNOWN))
        {
          delete_finish (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                          "Automatic deletion of unclaimed sensor fingerprints is disabled"));
          return;
        }
      if (!print || !print_get_tid (print, tid))
        {
          delete_finish (self, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
          return;
        }
      guint found = 0;
      for (guint i = 0; i < data[1]; i++)
        if (memcmp (data + 2 + i * GSDCP_RECORD_SIZE + 6, tid, GSDCP_TID_SIZE) == 0)
          {
            memcpy (self->delete_record, data + 2 + i * GSDCP_RECORD_SIZE, GSDCP_RECORD_SIZE);
            found++;
          }
      if (found != 1)
        {
          /* Already absent is a successful idempotent host deletion. */
          cache_record_list (self, data);
          delete_finish (self, found == 0 ? NULL : fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
          return;
        }
      GCancellable *cancel = fpi_device_get_cancellable (device);
      if (cancel && g_cancellable_is_cancelled (cancel))
        {
          delete_finish (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint deletion cancelled"));
          return;
        }
      self->delete_before = g_bytes_new (data, len);
      guint8 payload[2 + GSDCP_RECORD_SIZE] = { 1, 0 };
      memcpy (payload + 2, self->delete_record, GSDCP_RECORD_SIZE);
      payload[2 + 5] = 0; /* Stored-record flag is normalized on the wire. */
      self->delete_step = 1;
      goodix_cmd (self, 0xa7, 2, payload, sizeof (payload), FALSE, delete_step_cb);
      return;
    }
  gsize before_len;
  const guint8 *before = g_bytes_get_data (self->delete_before, &before_len);
  gboolean preserved = len + GSDCP_RECORD_SIZE == before_len &&
    records_preserved (before, before_len, data, len, self->delete_record);
  for (guint i = 0; i < data[1]; i++)
    if (memcmp (data + 2 + i * GSDCP_RECORD_SIZE + 6, self->delete_record + 6, GSDCP_TID_SIZE) == 0)
      preserved = FALSE;
  if (!preserved)
    {
      GError *failure = g_steal_pointer (&self->delete_error);
      delete_finish (self, failure ? failure : fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                      "Deletion readback did not confirm the requested removal and unchanged other fingerprints"));
      return;
    }
  cache_record_list (self, data);
  delete_finish (self, NULL);
}

static void
dev_delete (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  guint8 zero = 0;
  self->delete_step = 0;
  g_clear_error (&self->delete_error);
  g_clear_pointer (&self->delete_before, g_bytes_unref);
  goodix_cmd (self, CMD_LIST, 0, &zero, 1, FALSE, delete_step_cb);
}

/* -------------------------------------------------------------- probe / class */

static void
dev_probe (FpDevice *device)
{
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (device);

  if (!g_usb_device_open (usb, &error))
    {
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }
  g_usb_device_close (usb, NULL);
  fpi_device_probe_complete (device, NULL, NULL, NULL);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x6f94, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

/* ------------------------------------------------------ suspend / resume */

/* User-initiated cancel: cancel the pending finger read. */
static void
dev_cancel (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);

  if (self->cancel)
    g_cancellable_cancel (self->cancel);
}

/* System is about to suspend. If we are inside a cancellable finger read
 * (verify/identify waiting for a finger), pause it cleanly by cancelling
 * the read: cmd_receive_cb then completes the suspend with a NULL error (so
 * libfprint keeps the action alive across the sleep) and quietly finishes the
 * command, leaving the task SSM parked. In any other situation we cannot pause,
 * so we decline (NOT_SUPPORTED); libfprint then cancels the running action,
 * which is the pre-existing behaviour. */
static void
dev_suspend (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);

  if ((action == FPI_DEVICE_ACTION_VERIFY ||
       action == FPI_DEVICE_ACTION_IDENTIFY) &&
      self->cmd_ssm && self->cmd_cancelable && self->cancel)
    {
      fp_dbg ("goodixsdcp: dev_suspend during action %d: pausing finger read", action);
      self->suspended = TRUE;
      g_cancellable_cancel (self->cancel);
      /* fpi_device_suspend_complete() is called from cmd_receive_cb once the
       * cancelled read has unwound. */
    }
  else
    {
      fp_dbg ("goodixsdcp: dev_suspend (action %d, not in finger read): NOT_SUPPORTED",
              action);
      fpi_device_suspend_complete (device,
                                   fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
    }
}

/* System resumed. A deep suspend can drop the sensor's transport session, so we
 * do NOT just re-read: we set need_reinit and jump the parked task SSM to the
 * session-refresh prefix (GSDCP_VER_REINIT_POV), which re-runs the SDCP
 * handshake and then re-arms. If the sensor kept its session the handshake is
 * simply redone harmlessly; if it lost it, this restores it. */
static void
dev_resume (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);

  if (self->suspended && self->task_ssm)
    {
      fp_dbg ("goodixsdcp: dev_resume: re-establishing session then re-arming");
      self->suspended = FALSE;
      self->need_reinit = TRUE;
      self->seq = 0;                 /* fresh transport sequence after wake */
      g_clear_object (&self->cancel);
      self->cancel = g_cancellable_new ();
      fpi_device_resume_complete (device, NULL);
      fpi_ssm_jump_to_state (self->task_ssm, GSDCP_VER_REINIT_POV);
    }
  else
    {
      fp_dbg ("goodixsdcp: dev_resume: no paused action (task_ssm=%p), just clearing",
              (void *) self->task_ssm);
      self->suspended = FALSE;
      fpi_device_resume_complete (device, NULL);
    }
}

static void
fpi_device_goodixsdcp_init (FpiDeviceGoodixSdcp *self)
{
}

static void
fpi_device_goodixsdcp_finalize (GObject *object)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (object);

  if (self->list_result)
    g_ptr_array_free (self->list_result, TRUE);
  if (self->enroll_timer)
    g_source_remove (self->enroll_timer);
  gsdcp_session_clear (&self->session);
  g_clear_pointer (&self->enroll_before, g_bytes_unref);
  g_clear_pointer (&self->delete_before, g_bytes_unref);
  g_clear_error (&self->enroll_error);
  g_clear_error (&self->delete_error);
  g_clear_object (&self->cancel);
  G_OBJECT_CLASS (fpi_device_goodixsdcp_parent_class)->finalize (object);
}

static void
fpi_device_goodixsdcp_class_init (FpiDeviceGoodixSdcpClass *klass)
{
  GObjectClass *obj_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  obj_class->finalize = fpi_device_goodixsdcp_finalize;

  dev_class->id       = "goodixsdcp";
  dev_class->full_name = "Goodix GF3268 SDCP (Windows Hello) Fingerprint Sensor";
  dev_class->type     = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = 13;  /* native capture: five + eight updates */
  dev_class->temp_hot_seconds = -1;

  dev_class->probe    = dev_probe;
  dev_class->open     = dev_open;
  dev_class->close    = dev_close;
  dev_class->verify   = dev_verify_identify;
  dev_class->identify = dev_verify_identify;
  dev_class->enroll   = dev_enroll;
  dev_class->list     = dev_list;
  dev_class->delete   = dev_delete;
  dev_class->cancel   = dev_cancel;
  dev_class->suspend  = dev_suspend;
  dev_class->resume   = dev_resume;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}
