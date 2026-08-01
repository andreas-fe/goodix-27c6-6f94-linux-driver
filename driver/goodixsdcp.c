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
};

G_DEFINE_TYPE (FpiDeviceGoodixSdcp, fpi_device_goodixsdcp, FP_TYPE_DEVICE)

typedef void (*GoodixCmdCb) (FpiDeviceGoodixSdcp *self,
                             const guint8 *data, gsize len, GError *error);

typedef struct {
  guint8      cmd0;
  GoodixCmdCb callback;
} CmdData;

static void
cmd_data_free (CmdData *d) { g_free (d); }

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
  if (sidlen == 0 || sidlen > GSDCP_SID_MAXLEN)
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
  if (sidlen == 0 || sidlen > GSDCP_SID_MAXLEN)
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
  guint8 cmd0, cmd1, seq;
  const guint8 *payload;
  gsize payload_len;

  if (error)
    {
      /* A read cancelled because the system is suspending: park the command
       * SSM (don't fail the verify). It is re-issued from GSDCP_CMD_RESUME. */
      if (self->suspended &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
          fpi_ssm_jump_to_state (transfer->ssm, GSDCP_CMD_SUSPENDED);
          return;
        }
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* zero-length or ACK-only: re-arm the same read */
  if (transfer->actual_length == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, GSDCP_CMD_RECV);
      return;
    }

  if (!gsdcp_parse_packet (transfer->buffer, transfer->actual_length,
                           &cmd0, &cmd1, &seq, &payload, &payload_len))
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "malformed packet"));
      return;
    }

  if (cmd0 == CMD_ACK)
    {
      /* device ACK: keep reading for the real response */
      fpi_ssm_jump_to_state (transfer->ssm, GSDCP_CMD_RECV);
      return;
    }

  if (data->callback)
    data->callback (self, payload, payload_len, NULL);
  fpi_ssm_mark_completed (transfer->ssm);
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

    case GSDCP_CMD_SUSPENDED:
      /* Parked while the system is suspended. Tell libfprint the suspend is
       * configured (NULL error => the verify keeps running after resume, so
       * libfprint does NOT cancel it). The SSM waits here until dev_resume
       * jumps it to GSDCP_CMD_RESUME. */
      fpi_device_suspend_complete (dev, NULL);
      break;

    case GSDCP_CMD_RESUME:
      /* Woke up: acknowledge the resume and re-issue the finger read. */
      fpi_device_resume_complete (dev, NULL);
      fpi_ssm_jump_to_state (ssm, GSDCP_CMD_RECV);
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

  pkt_len = gsdcp_build_package (cmd0, cmd1, self->seq++, payload, payload_len,
                                 buf, sizeof (buf));
  g_assert (pkt_len != 0);

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, EP_OUT, pkt_len);
  memcpy (transfer->buffer, buf, pkt_len);

  data = g_new0 (CmdData, 1);
  data->cmd0 = cmd0;
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
  g_assert (inner_len != 0);
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
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  fpi_ssm_next_state (self->task_ssm);
}

static void
init_list_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  guint count, i;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  if (self->list_result)
    g_ptr_array_free (self->list_result, TRUE);
  self->list_result = g_ptr_array_new_with_free_func (g_object_unref);

  /* payload: [2B count][count * 100B record] */
  if (len >= 2)
    {
      count = ((guint) data[0] << 8) | data[1];
      for (i = 0; i < count; i++)
        {
          const guint8 *rec = data + 2 + (gsize) i * GSDCP_RECORD_SIZE;
          if (2 + (gsize) (i + 1) * GSDCP_RECORD_SIZE > len)
            break;
          g_ptr_array_add (self->list_result,
                           g_object_ref_sink (print_from_record (self, rec)));
        }
    }
  fpi_ssm_next_state (self->task_ssm);
}

static void
init_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  guint8 zero = 0x00;
  guint8 b0arg[1] = { 0x00 };

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
init_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);

  self->task_ssm = NULL;
  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (device);

  if (!g_usb_device_reset (usb, &error) ||
      !g_usb_device_claim_interface (usb, USB_INTERFACE, 0, &error))
    {
      fpi_device_open_complete (device, error);
      return;
    }
  self->seq = 0;
  self->task_ssm = fpi_ssm_new (device, init_run_state, GSDCP_INIT_NUM_STATES);
  fpi_ssm_start (self->task_ssm, init_ssm_done);
}

static void
dev_close (FpDevice *device)
{
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (device);

  g_usb_device_release_interface (usb, USB_INTERFACE, 0, &error);
  fpi_device_close_complete (device, error);
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

  if (len >= GSDCP_RECORD_SIZE + 8)
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
      /* clean read but no match: report FAIL, then wait for finger lift so the
       * next verify starts fresh (avoids hammering the sensor on wrong finger) */
      report_match (self, NULL);
      fpi_ssm_next_state (self->task_ssm);   /* -> GSDCP_VER_WAIT_LIFT */
    }
  else
    {
      /* no clean finger read: ask to retry */
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
    }
}

static void
verify_lift_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  if (len >= 1 && data[0] == 0xc0)
    {
      /* finger removed -> verify done */
      fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                               FP_FINGER_STATUS_NONE,
                                               FP_FINGER_STATUS_PRESENT);
      fpi_ssm_mark_completed (self->task_ssm);
    }
  else
    {
      /* still on the reader: poll again gently */
      fpi_ssm_jump_to_state_delayed (self->task_ssm, GSDCP_VER_WAIT_LIFT, 200);
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

static void
verify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  guint8 nonce[32];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GSDCP_VER_ARM:
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
    case GSDCP_VER_WAIT_LIFT:
      goodix_cmd (self, CMD_ARM, 0x00, ARM_DETECT, sizeof (ARM_DETECT), FALSE, verify_lift_cb);
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
  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  self->task_ssm = fpi_ssm_new (device, verify_run_state, GSDCP_VER_NUM_STATES);
  fpi_ssm_start (self->task_ssm, verify_ssm_done);
}

/* --------------------------------------------------------- enroll (bind) */

/* Enroll = "bind": user presents an already-(Windows-)enrolled finger, the chip
 * matches it, and we register the matched on-chip template as an FpPrint. */
static void
enroll_match_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT,
                                           FP_FINGER_STATUS_NONE);

  fp_dbg ("a5 enroll response: %zu bytes, first=%02x", len, len ? data[0] : 0);

  if (len >= GSDCP_RECORD_SIZE + 8)
    {
      /* matched an on-chip template -> bind it to the requested print */
      FpPrint *print = NULL;
      fpi_device_get_enroll_data (dev, &print);
      apply_record_to_print (print, data + 8);
      fpi_device_enroll_progress (dev, 1, NULL, NULL);
      fpi_ssm_mark_completed (self->task_ssm);
    }
  else if (len >= 1 && data[0] == 0x01)
    {
      /* clean read but no match: not (yet) enrolled in Windows Hello */
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                             "Finger not recognised. Only fingers already "
                             "enrolled in Windows Hello can be added here "
                             "(enrollment of new fingers is TPM-bound). "
                             "Place a Windows-Hello-enrolled finger."));
    }
  else
    {
      /* no clean capture (0x03 wrong-state / 0xff no-finger / short) */
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
    }
}

static void
enroll_arm_cb (FpiDeviceGoodixSdcp *self, const guint8 *data, gsize len, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  if (len >= 1 && data[0] == 0xc0)
    {
      fpi_ssm_jump_to_state (self->task_ssm, GSDCP_VER_ARM);
      return;
    }
  fpi_ssm_next_state (self->task_ssm);
}

static void
enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  guint8 nonce[32];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GSDCP_VER_ARM:
      goodix_cmd (self, CMD_ARM, 0x00, ARM_DETECT, sizeof (ARM_DETECT), TRUE, enroll_arm_cb);
      break;
    case GSDCP_VER_MATCH:
      for (int i = 0; i < 32; i++)
        nonce[i] = (guint8) g_random_int_range (0, 256);
      goodix_cmd (self, CMD_MATCH, 0x00, nonce, sizeof (nonce), TRUE, enroll_match_cb);
      break;
    }
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (dev);
  FpPrint *print = NULL;

  self->task_ssm = NULL;
  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }
  fpi_device_get_enroll_data (dev, &print);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);

  self->suspended = FALSE;
  g_clear_object (&self->cancel);
  self->cancel = g_cancellable_new ();

  self->task_ssm = fpi_ssm_new (device, enroll_run_state, GSDCP_VER_NUM_STATES);
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

/* Removing a print only drops the host-side binding; the on-chip template
 * (owned by the Windows-Hello enrollment) is left untouched on purpose. */
static void
dev_delete (FpDevice *device)
{
  fpi_device_delete_complete (device, NULL);
}

static void
dev_clear_storage (FpDevice *device)
{
  fpi_device_clear_storage_complete (device, NULL);
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
 * (verify/identify/enroll waiting for a finger), pause it cleanly: cancel the
 * read, which lands in GSDCP_CMD_SUSPENDED and completes the suspend with a
 * NULL error so libfprint keeps the action alive across the sleep. In any
 * other situation we cannot pause, so we decline (NOT_SUPPORTED); libfprint
 * then cancels the running action, which is the pre-existing behaviour. */
static void
dev_suspend (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);

  if ((action == FPI_DEVICE_ACTION_VERIFY ||
       action == FPI_DEVICE_ACTION_IDENTIFY ||
       action == FPI_DEVICE_ACTION_ENROLL) &&
      self->cmd_ssm && self->cmd_cancelable && self->cancel)
    {
      self->suspended = TRUE;
      g_cancellable_cancel (self->cancel);
      /* fpi_device_suspend_complete() is called from GSDCP_CMD_SUSPENDED once
       * the cancelled read has unwound. */
    }
  else
    {
      fpi_device_suspend_complete (device,
                                   fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
    }
}

/* System resumed. Re-arm the finger read with a fresh cancellable and let the
 * paused command SSM continue. */
static void
dev_resume (FpDevice *device)
{
  FpiDeviceGoodixSdcp *self = FPI_DEVICE_GOODIXSDCP (device);

  if (self->suspended && self->cmd_ssm &&
      fpi_ssm_get_cur_state (self->cmd_ssm) == GSDCP_CMD_SUSPENDED)
    {
      self->suspended = FALSE;
      g_clear_object (&self->cancel);
      self->cancel = g_cancellable_new ();
      /* GSDCP_CMD_RESUME calls fpi_device_resume_complete() and re-issues. */
      fpi_ssm_jump_to_state (self->cmd_ssm, GSDCP_CMD_RESUME);
    }
  else
    {
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
  dev_class->nr_enroll_stages = 1;   /* bind = one presentation */
  dev_class->temp_hot_seconds = -1;

  dev_class->probe    = dev_probe;
  dev_class->open     = dev_open;
  dev_class->close    = dev_close;
  dev_class->verify   = dev_verify_identify;
  dev_class->identify = dev_verify_identify;
  dev_class->enroll   = dev_enroll;
  dev_class->list     = dev_list;
  dev_class->delete   = dev_delete;
  dev_class->clear_storage = dev_clear_storage;
  dev_class->cancel   = dev_cancel;
  dev_class->suspend  = dev_suspend;
  dev_class->resume   = dev_resume;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}
