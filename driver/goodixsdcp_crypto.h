/*
 * Goodix GF3268 SDCP driver - transport crypto + packet framing
 *
 * Copyright (C) 2026
 *
 * Session transport crypto and Goodix packet framing for the GF3268
 * (Windows Hello / SDCP) sensor, VID 27c6 PID 6f94. Ported from the verified
 * Python reference (scratch/goodix_crypto.py, scratch/goodix_gf3268.py):
 * fixed AES-128-CBC + HMAC-SHA256 session keys (device/session independent),
 * verified 159/159 against captured traffic.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

/* Packet framing -------------------------------------------------------- */

#define GSDCP_HEADER_SIZE 8
#define GSDCP_CRC_SIZE    4

/* CRC8 over the first 6 header bytes (poly 0x1070<<3, then ~(crc>>8)). */
guint8 gsdcp_crc8 (const guint8 *data, gsize len);

/* Standard reflected CRC32 (zlib/binascii compatible). */
guint32 gsdcp_crc32 (const guint8 *data, gsize len);

/*
 * Build a full Goodix packet:  [8B header] [payload] [CRC32], then zero-pad
 * the whole thing up to a multiple of 64 bytes. Writes into @out (capacity
 * @out_cap) and returns the total padded length, or 0 on overflow.
 */
gsize gsdcp_build_package (guint8        cmd0,
                           guint8        cmd1,
                           guint8        seq,
                           const guint8 *payload,
                           gsize         payload_len,
                           guint8       *out,
                           gsize         out_cap);

/*
 * Parse a received packet. On success returns TRUE and sets cmd0, cmd1, seq
 * and points payload at the data inside @raw (with payload_len). The payload
 * excludes the trailing CRC32.
 */
gboolean gsdcp_parse_packet (const guint8  *raw,
                             gsize          len,
                             guint8        *cmd0,
                             guint8        *cmd1,
                             guint8        *seq,
                             const guint8 **payload,
                             gsize         *payload_len);

/* Session transport crypto (e3 channel) --------------------------------- */

/*
 * Encrypt @pt into the inner e3 payload:
 *   MAC(32) || 01 ff || plaintext_len(LE32) || IV(16) || AES-128-CBC(PKCS7(pt))
 * Writes into @out (capacity @out_cap); returns the inner length or 0 on error.
 */
gsize gsdcp_encrypt (const guint8 *pt,
                     gsize         pt_len,
                     guint8       *out,
                     gsize         out_cap);

/*
 * Decrypt an inner e3 payload (as produced by gsdcp_encrypt / received from
 * the sensor). Verifies the HMAC. Writes plaintext into @out (capacity
 * @out_cap); returns plaintext length, or -1 on error / MAC mismatch.
 */
gssize gsdcp_decrypt (const guint8 *inner,
                      gsize         inner_len,
                      guint8       *out,
                      gsize         out_cap);

/*
 * Is @inner an encrypted e3 envelope (starts with MAC(32) then 0x01 0xff)?
 * Used to tell encrypted responses from plaintext ones.
 */
gboolean gsdcp_is_encrypted (const guint8 *inner, gsize inner_len);

G_END_DECLS
