/*
 * Copyright (C) 2014  NXP Semiconductors  All rights reserved.
 *
 * Author: Clément Perrochaud <clement.perrochaud@nxp.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __LOCAL_NXP_H_
#define __LOCAL_NXP_H_

#define NXP_VENDOR_ID 0x00006037
#define NXP_CONFIG_MAX_PARAM_LEN 255

enum nxp_vendor_subcmd {
	NXP_VENDOR_SUBCMD_SET_NCI_CONFIG,
	NXP_VENDOR_SUBCMD_SET_PROPRIETARY_CONFIG,
	NXP_VENDOR_SUBCMD_GET_NCI_CONFIG,
	NXP_VENDOR_SUBCMD_GET_PROPRIETARY_CONFIG,
	NXP_VENDOR_SUBCMD_ENABLE_PROPRIETARY_EXTENSIONS,
	NXP_VENDOR_SUBCMD_ANTENNA_SELFTEST,
/* private: internal use only */
	__NXP_VENDOR_SUBCMD_AFTER_LAST
};

enum nxp_vendor_rsp {
	NXP_VENDOR_RSP_PROPRIETARY_EXTENSIONS	= 0x0F02,
	NXP_VENDOR_RSP_ANTENNA_SELFTEST		= 0x0F3D,
/* private: internal use only */
	__NXP_VENDOR_RSP_AFTER_LAST
};

struct nxp_set_nci_config_param_hdr {
	__u8 id;
	__u8 len;
} __packed;

struct nxp_set_proprietary_config_param_hdr {
	__u16 id;
	__u8 len;
} __packed;

typedef __u8 nxp_get_nci_config_param_hdr;

typedef __u16 nxp_get_proprietary_config_param_hdr;

enum nxp_antenna_selftest_measurement {
	NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_CURRENT		= 0x01,
	NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_AGC		= 0x02,
	NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_AGC_FIXED_NFCLD	= 0x04,
	NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_AGC_DIFF	= 0x08,
	NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_RF_FIELD	= 0x20,
};

#define NCI_OP_PROPRIETARY_NXP_ENABLE_PROPRIETARY_EXTENSIONS_CMD \
		nci_opcode_pack(NCI_GID_PROPRIETARY, 0x02)
#define NCI_OP_PROPRIETARY_NXP_ANTENNA_SELFTEST_CMD \
		nci_opcode_pack(NCI_GID_PROPRIETARY, 0x3D)

#ifndef NCI_OP_CORE_GET_CONFIG_CMD
#define NCI_OP_CORE_GET_CONFIG_CMD	nci_opcode_pack(NCI_GID_CORE, 0x03)
#endif

#ifndef NCI_OP_CORE_GET_CONFIG_RSP
#define NCI_OP_CORE_GET_CONFIG_RSP	nci_opcode_pack(NCI_GID_CORE, 0x03)
#endif

#endif /* __LOCAL_NXP_H_ */
