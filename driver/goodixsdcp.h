/*
 * Goodix GF3268 SDCP (Windows Hello) fingerprint driver for libfprint
 *
 * Copyright (C) 2026
 *
 * Match-on-chip verify driver for the Goodix GF3268 (VID 27c6 PID 6f94), the
 * SDCP / Windows-Hello sensor found e.g. in the Honor MagicBook Art 14.
 * Native enrollment uses a fresh SDCP session and the verified thirteen-sample
 * policy for firmware 01010032. Empty template stores get a fresh local identity;
 * nonempty stores reuse their Type-4 metadata. Factory provisioning is untested:
 *   - list     -> read the on-chip template records (a6 READ_OTP)
 *   - enroll   -> capture, duplicate check, single SDCP commit, readback
 *   - verify   -> a5 SDCP match against the on-chip templates
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixSdcp, fpi_device_goodixsdcp, FPI,
                      DEVICE_GOODIXSDCP, FpDevice)

/* On-chip template record: [6B hdr][16B tid][16B 0][32B mac][1B sidlen][28B sid][00] */
#define GSDCP_RECORD_SIZE 100
#define GSDCP_TID_SIZE    16
#define GSDCP_SID_MAXLEN  28

/* Command SSM: send -> receive (skipping ACKs). */
typedef enum {
  GSDCP_CMD_SEND = 0,
  GSDCP_CMD_RECV,
  GSDCP_CMD_NUM_STATES,
} GsdcpCmdState;

/* Open / init SSM. */
typedef enum {
  GSDCP_INIT_POV = 0,        /* e1 04 */
  GSDCP_INIT_HELLO2,         /* e3 02 HELLO */
  GSDCP_INIT_HELLO0,         /* e3 00 HELLO -> cert flight (session up) */
  GSDCP_INIT_CAL,            /* b0 02 */
  GSDCP_INIT_PSK,            /* e0 01 */
  GSDCP_INIT_LIST,           /* a6 00 -> template records */
  GSDCP_INIT_NUM_STATES,
} GsdcpInitState;

/* Verify / identify SSM.
 * The GSDCP_VER_REINIT_* states form an optional session-refresh prefix that is
 * only executed when self->need_reinit is set (after a system resume, where the
 * sensor may have lost its transport session during deep suspend). On a normal
 * start the first state jumps straight to GSDCP_VER_ARM, so there is no overhead. */
typedef enum {
  GSDCP_VER_REINIT_POV = 0,  /* e1 04  (only if need_reinit) */
  GSDCP_VER_REINIT_HELLO2,   /* e3 02 HELLO */
  GSDCP_VER_REINIT_HELLO0,   /* e3 00 HELLO -> cert flight (session up) */
  GSDCP_VER_REINIT_CAL,      /* b0 02 */
  GSDCP_VER_REINIT_PSK,      /* e0 01 */
  GSDCP_VER_ARM,             /* a2 finger detect */
  GSDCP_VER_MATCH,           /* a5 SDCP match */
  GSDCP_VER_NUM_STATES,
} GsdcpVerState;

typedef enum {
  GSDCP_EN_VERSION,
  GSDCP_EN_LIST,
  GSDCP_EN_POV,
  GSDCP_EN_HELLO2,
  GSDCP_EN_HELLO0,
  GSDCP_EN_CAL,
  GSDCP_EN_SHIELD,
  GSDCP_EN_BEGIN,
  GSDCP_EN_RECONNECT2,
  GSDCP_EN_RECONNECT1,
  GSDCP_EN_SAMPLE_CAL,
  GSDCP_EN_ARM,
  GSDCP_EN_UPDATE,
  GSDCP_EN_DUPLICATE,
  GSDCP_EN_COMMIT,
  GSDCP_EN_POST_LIST,
  GSDCP_EN_OFF,
  GSDCP_EN_NUM_STATES,
} GsdcpEnrollState;
