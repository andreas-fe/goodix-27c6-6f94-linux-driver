/* Isolated goodixmoc trial; use ONLY with goodixmoc-6f94-safe.patch applied.
 * Does not install anything, delete prints, or modify fprintd's files.
 * Default operation is open/list/close. Enrollment requires --enroll explicitly.
 */
#include <libfprint/fprint.h>
#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static gboolean
cancel_operation (gpointer data)
{
  g_cancellable_cancel (G_CANCELLABLE (data));
  return G_SOURCE_CONTINUE;
}

static void
progress (FpDevice *device, gint stage, FpPrint *print,
          gpointer data, GError *error)
{
  (void) print;
  (void) data;
  if (error)
    g_print ("RETRY %s\n", error->message);
  else
    g_print ("PROGRESS %d/%d: Lift the finger fully and place it again.\n",
             stage, fp_device_get_nr_enroll_stages (device));
  fflush (stdout);
}

static gboolean
save_print (FpPrint *print, int fd, GError **error)
{
  g_autofree guint8 *bytes = NULL;
  gsize length = 0, offset = 0;
  if (!fp_print_serialize (print, &bytes, &length, error))
    return FALSE;
  gboolean ok = TRUE;
  while (offset < length)
    {
      ssize_t count = write (fd, bytes + offset, length - offset);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        {
          g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
                       "Cannot write print reference: %s", g_strerror (errno));
          ok = FALSE;
          break;
        }
      offset += (gsize) count;
    }
  if (ok && fsync (fd) != 0)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
                   "Cannot sync print reference: %s", g_strerror (errno));
      ok = FALSE;
    }
  return ok;
}

static gboolean
contains_print (GPtrArray *prints, FpPrint *print)
{
  for (guint i = 0; i < prints->len; i++)
    if (fp_print_equal (print, g_ptr_array_index (prints, i)))
      return TRUE;
  return FALSE;
}

static gboolean
contains_originals (GPtrArray *before, GPtrArray *after)
{
  for (guint i = 0; i < before->len; i++)
    {
      if (!contains_print (after, g_ptr_array_index (before, i)))
        return FALSE;
    }
  return TRUE;
}

int
main (int argc, char **argv)
{
  setbuf (stdout, NULL);
  /* Debug logging in upstream prints template identifiers. Keep it disabled. */
  g_unsetenv ("G_MESSAGES_DEBUG");
  gboolean enroll = argc == 4 && strcmp (argv[1], "--enroll") == 0;
  gboolean verify = argc == 3 && strcmp (argv[1], "--verify") == 0;
  gboolean inspect = argc == 1 || (argc == 2 && strcmp (argv[1], "--inspect") == 0);
  if (!enroll && !verify && !inspect)
    {
      g_printerr ("Usage: %s [--inspect | --enroll FINGER_NUMBER NEW_REFERENCE | --verify REFERENCE]\n", argv[0]);
      return 2;
    }
  gchar *finger_end = NULL;
  gint64 finger = enroll ? g_ascii_strtoll (argv[2], &finger_end, 10) : FP_FINGER_UNKNOWN;
  if (enroll && (!finger_end || *finger_end || finger < FP_FINGER_FIRST ||
                 finger > FP_FINGER_LAST))
    {
      g_printerr ("Invalid finger number.\n");
      return 2;
    }
  /* Reserve the reference before any sensor operation, never after commit. */
  int reference_fd = -1;
  gboolean committed = FALSE;
  if (enroll)
    {
      reference_fd = open (argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
      if (reference_fd < 0)
        {
          g_printerr ("REFERENCE_CREATE_FAILED %s\n", g_strerror (errno));
          return 2;
        }
    }
  g_autoptr(GError) error = NULL;
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  guint timer = g_timeout_add_seconds (180, cancel_operation, cancel);
  guint sigint = g_unix_signal_add (SIGINT, cancel_operation, cancel);
  g_autoptr(FpContext) context = fp_context_new ();
  GPtrArray *devices = fp_context_get_devices (context);
  FpDevice *device = NULL;
  guint matches = 0;
  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *candidate = g_ptr_array_index (devices, i);
      if (g_strcmp0 (fp_device_get_driver (candidate), "goodixmoc") == 0)
        {
          device = candidate;
          matches++;
        }
    }
  int result = 1;
  if (matches != 1)
    {
      g_printerr ("Expected exactly one goodixmoc device; found %u.\n", matches);
      goto done;
    }
  if (!fp_device_open_sync (device, cancel, &error))
    {
      g_printerr ("OPEN_FAILED %s\n", error->message);
      goto done;
    }
  {
    g_autoptr(GPtrArray) before = fp_device_list_prints_sync (device, cancel, &error);
    if (!before)
      {
        g_printerr ("LIST_FAILED %s\n", error->message);
        goto close_device;
      }
    g_print ("OPEN_OK driver=goodixmoc existing_templates=%u enroll_stages=%d\n",
             before->len, fp_device_get_nr_enroll_stages (device));
    if (inspect)
      result = 0;
    else if (enroll)
      {
        /* Historical device capacity is three. Never delete to make space. */
        if (before->len >= 3)
          {
            g_printerr ("STORE_FULL: No enrollment attempted; existing templates preserved.\n");
            goto close_device;
          }
        g_autoptr(FpPrint) template = g_object_ref_sink (fp_print_new (device));
        fp_print_set_finger (template, (FpFinger) finger);
        fp_print_set_username (template, g_get_user_name ());
        fp_print_set_description (template, "isolated-linux-enrollment-trial");
        g_print ("READY_ENROLL: Place the new finger; lift it fully between attempts.\n");
        g_autoptr(FpPrint) enrolled = fp_device_enroll_sync (
          device, template, cancel, progress, NULL, &error);
        if (!enrolled)
          g_printerr ("ENROLL_FAILED %s\n", error ? error->message : "unknown error");
        else
          {
            committed = TRUE;
            if (!save_print (enrolled, reference_fd, &error))
              g_printerr ("ENROLL_COMMITTED_REFERENCE_SAVE_FAILED %s\n", error->message);
            else
              {
                g_print ("ENROLL_COMMITTED reference_saved=true\n");
                result = 0;
              }
          }
        g_clear_error (&error);
        g_autoptr(GPtrArray) after = fp_device_list_prints_sync (device, NULL, &error);
        if (!after)
          {
            g_printerr ("POST_LIST_FAILED %s\n", error->message);
            result = 1;
          }
        else
          {
            gboolean kept = contains_originals (before, after);
            gboolean reference_present = enrolled && contains_print (after, enrolled);
            g_print ("POST_CHECK templates=%u originals_preserved=%s new_reference_present=%s\n",
                     after->len, kept ? "true" : "false", reference_present ? "true" : "false");
            if (!kept || (enrolled && (after->len != before->len + 1 || !reference_present)))
              result = 1;
            if (!enrolled && kept && after->len == before->len + 1)
              {
                /* A4 may have succeeded before a later shield-off failure.
                 * Recover the one new reference; never retry enrollment here. */
                committed = TRUE;
                for (guint j = 0; j < after->len; j++)
                  {
                    FpPrint *added = g_ptr_array_index (after, j);
                    if (!contains_print (before, added))
                      {
                        if (save_print (added, reference_fd, &error))
                          g_print ("REFERENCE_RECOVERED_AFTER_API_ERROR: Verify before any new enrollment.\n");
                        else
                          g_printerr ("REFERENCE_RECOVERY_FAILED %s\n", error->message);
                        break;
                      }
                  }
              }
          }
      }
    else
      {
        g_autofree gchar *bytes = NULL;
        gsize length = 0;
        if (!g_file_get_contents (argv[2], &bytes, &length, &error))
          {
            g_printerr ("REFERENCE_READ_FAILED %s\n", error->message);
            goto close_device;
          }
        g_autoptr(FpPrint) reference = fp_print_deserialize ((guint8 *) bytes, length, &error);
        if (!reference)
          {
            g_printerr ("REFERENCE_PARSE_FAILED %s\n", error->message);
            goto close_device;
          }
        gboolean match = FALSE;
        g_print ("READY_VERIFY: Place the finger.\n");
        if (!fp_device_verify_sync (device, reference, cancel, NULL, NULL, &match, NULL, &error))
          g_printerr ("VERIFY_FAILED %s\n", error->message);
        else
          {
            g_print ("VERIFY_RESULT match=%s\n", match ? "true" : "false");
            result = match ? 0 : 3;
          }
      }
  }
close_device:
  g_clear_error (&error);
  if (!fp_device_close_sync (device, NULL, &error))
    {
      g_printerr ("CLOSE_FAILED %s\n", error->message);
      result = 1;
    }
done:
  g_source_remove (timer);
  g_source_remove (sigint);
  if (reference_fd >= 0)
    {
      close (reference_fd);
      if (!committed)
        unlink (argv[3]);
    }
  return result;
}
