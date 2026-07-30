/*
 * Goodix GF3268 SDCP (Windows Hello) fingerprint driver for libfprint
 *
 * Copyright (C) 2026
 *
 * Match-on-chip verify driver for the Goodix GF3268 (VID 27c6 PID 6f94), the
 * SDCP / Windows-Hello sensor found e.g. in the Honor MagicBook Art 14.
 * Enrollment of new fingers is TPM-bound and must be done under Windows Hello;
 * this driver therefore uses the templates already stored on the chip:
 *   - list     -> read the on-chip template records (a6 READ_OTP)
 *   - enroll   -> "bind": the user presents an already-enrolled finger, the
 *                 chip matches it and we register the matched on-chip template
 *                 as an FpPrint (so fprintd/KDE can use it)
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
#define GSDCP_SID_MAXLEN  40

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

/* Verify / identify / enroll-bind SSM. */
typedef enum {
  GSDCP_VER_ARM = 0,         /* a2 finger detect */
  GSDCP_VER_MATCH,           /* a5 SDCP match */
  GSDCP_VER_WAIT_LIFT,       /* after no-match: wait for finger removal */
  GSDCP_VER_NUM_STATES,
} GsdcpVerState;
