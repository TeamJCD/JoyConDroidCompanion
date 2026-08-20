#pragma once

#include <stdint.h>

#define BTLINKMODE_PATH "/dev/btlinkmode"

/* Values written to BTLINKMODE_PATH, matching HCI Mode Change's Current_Mode
 * field (Bluetooth Core Spec, Vol 2, Part E, 7.7.4). */
#define BT_LINK_MODE_ACTIVE 0
#define BT_LINK_MODE_HOLD   1
#define BT_LINK_MODE_SNIFF  2
#define BT_LINK_MODE_PARK   3

/* Defined in mode_change.c, shared with mode_change_shape_scan.c so both
 * Mode-Change-Hook strategies publish through the same fd/logic. */
void mode_change_publish(uint32_t mode);
