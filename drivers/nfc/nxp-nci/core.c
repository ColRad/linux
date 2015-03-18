/*
 * Generic driver for NXP NCI NFC chips
 *
 * Copyright (C) 2014  NXP Semiconductors  All rights reserved.
 *
 * Authors: Clément Perrochaud <clement.perrochaud@nxp.com>
 *
 * Derived from PN544 device driver:
 * Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/nfc.h>
#include <linux/platform_data/nxp-nci.h>

#include <net/nfc/nci_core.h>

#include "nxp-nci.h"

#define NXP_NCI_HDR_LEN	4

#define NXP_NCI_NFC_PROTOCOLS	NFC_PROTO_JEWEL_MASK | \
				NFC_PROTO_MIFARE_MASK | \
				NFC_PROTO_FELICA_MASK | \
				NFC_PROTO_ISO14443_MASK | \
				NFC_PROTO_ISO14443_B_MASK | \
				NFC_PROTO_ISO15693_MASK | \
				NFC_PROTO_NFC_DEP_MASK

static int nxp_nci_open(struct nci_dev *ndev)
{
	struct nxp_nci_info *info = nci_get_drvdata(ndev);
	int r = 0;

	mutex_lock(&info->info_lock);

	if (info->mode != NXP_NCI_MODE_COLD) {
		r = -EBUSY;
		goto open_exit;
	}

	if (info->phy_ops->enable)
		r = info->phy_ops->enable(info->phy_id);

	info->mode = NXP_NCI_MODE_NCI;

open_exit:
	mutex_unlock(&info->info_lock);
	return r;
}

static int nxp_nci_close(struct nci_dev *ndev)
{
	struct nxp_nci_info *info = nci_get_drvdata(ndev);
	int r = 0;

	mutex_lock(&info->info_lock);

	if (info->phy_ops->disable)
		r = info->phy_ops->disable(info->phy_id);

	info->mode = NXP_NCI_MODE_COLD;

	mutex_unlock(&info->info_lock);
	return r;
}

static int nxp_nci_send(struct nci_dev *ndev, struct sk_buff *skb)
{
	struct nxp_nci_info *info = nci_get_drvdata(ndev);
	int r;

	if (!info->phy_ops->write) {
		r = -ENOTSUPP;
		goto send_exit;
	}

	if (info->mode != NXP_NCI_MODE_NCI) {
		r = -EINVAL;
		goto send_exit;
	}

	r = info->phy_ops->write(info->phy_id, skb);
	if (r < 0)
		kfree_skb(skb);

send_exit:
	return r;
}

static int nxp_nci_recv_proprietary_rsp_packet(struct nci_dev *ndev, u16 opcode,
					       struct sk_buff *skb)
{
	u32 subcmd;

	switch (opcode) {
	case NCI_OP_CORE_SET_CONFIG_RSP:
		if (skb->len > 0 && skb->data[0] == 0xA0)
			subcmd = NXP_VENDOR_SUBCMD_SET_PROPRIETARY_CONFIG;
		else
			subcmd = NXP_VENDOR_SUBCMD_SET_NCI_CONFIG;
		break;
	case NCI_OP_CORE_GET_CONFIG_RSP:
		if (skb->len > 0 && skb->data[0] == 0xA0)
			subcmd = NXP_VENDOR_SUBCMD_GET_PROPRIETARY_CONFIG;
		else
			subcmd = NXP_VENDOR_SUBCMD_GET_NCI_CONFIG;
		break;
	case NXP_VENDOR_RSP_PROPRIETARY_EXTENSIONS:
		subcmd = NXP_VENDOR_SUBCMD_ENABLE_PROPRIETARY_EXTENSIONS;
		break;
	case NXP_VENDOR_RSP_ANTENNA_SELFTEST:
		subcmd = NXP_VENDOR_SUBCMD_ANTENNA_SELFTEST;
		break;
	default:
		return -ENOSYS;
	}

	return nfc_vendor_rsp(ndev->nfc_dev, NXP_VENDOR_ID, subcmd, skb->len,
			      skb->data);
}

static struct nci_ops nxp_nci_ops = {
	.open = nxp_nci_open,
	.close = nxp_nci_close,
	.send = nxp_nci_send,
	.fw_download = nxp_nci_fw_download,
	.recv_proprietary_rsp_packet = nxp_nci_recv_proprietary_rsp_packet,
};

static int nxp_nci_proprietary_cmd(struct nfc_dev *dev, u16 cmd, void *data,
				   size_t data_len)
{
	struct nci_dev *ndev = nfc_get_drvdata(dev);
	struct sk_buff *skb;
	struct nci_ctrl_hdr *hdr;
	long completion_rc;
	int rc = 0;

	ndev->req_status = NCI_REQ_PEND;

	init_completion(&ndev->req_completion);

	skb = nci_skb_alloc(ndev,
			    (NCI_CTRL_HDR_SIZE + data_len),
			    GFP_KERNEL);
	if (!skb) {
		pr_err("no memory for command\n");
		return -ENOMEM;
	}

	hdr = (struct nci_ctrl_hdr *) skb_put(skb, NCI_CTRL_HDR_SIZE);
	hdr->gid = nci_opcode_gid(cmd);
	hdr->oid = nci_opcode_oid(cmd);
	hdr->plen = data_len;

	nci_mt_set((__u8 *)hdr, NCI_MT_CMD_PKT);
	nci_pbf_set((__u8 *)hdr, NCI_PBF_LAST);

	if (data_len > 0)
		memcpy(skb_put(skb, data_len), data, data_len);

	skb_queue_tail(&ndev->cmd_q, skb);
	queue_work(ndev->cmd_wq, &ndev->cmd_work);

	completion_rc = wait_for_completion_interruptible_timeout(
				&ndev->req_completion,
				msecs_to_jiffies(NCI_SET_CONFIG_TIMEOUT));

	pr_debug("wait_for_completion return %ld\n", completion_rc);

	if (completion_rc > 0) {
		switch (ndev->req_status) {
		case NCI_REQ_DONE:
			rc = nci_to_errno(ndev->req_result);
			break;

		case NCI_REQ_CANCELED:
			rc = -ndev->req_result;
			break;

		default:
			rc = -ETIMEDOUT;
			break;
		}
	} else {
		pr_err("wait_for_completion_interruptible_timeout failed %ld\n",
		       completion_rc);

		rc = ((completion_rc == 0) ? (-ETIMEDOUT) : (completion_rc));
	}

	ndev->req_status = ndev->req_result = 0;

	return rc;
}

static int nxp_nci_set_nci_config(struct nfc_dev *dev, void *data,
				  size_t data_len)
{
	unsigned char i, fields;
	unsigned int data_index = 1;
	unsigned char* param = (unsigned char*) data;
	struct nxp_set_nci_config_param_hdr* param_hdr;
	int r;

	if (data_len < 1)
		return -EINVAL;

	fields = param[0];

	for (i = 0; i < fields; i++) {
		param_hdr = (struct nxp_set_nci_config_param_hdr*)
			&param[data_index];
		data_index +=
			sizeof(struct nxp_set_nci_config_param_hdr);
		if (data_index >= data_len)
			return -EINVAL;
		data_index += param_hdr->len;
	}

	if (data_index != data_len)
		return -EINVAL;

	r = nxp_nci_proprietary_cmd(dev, NCI_OP_CORE_SET_CONFIG_CMD,
				    data, data_len);

	nfc_vendor_rsp(dev, NXP_VENDOR_ID,
		       NXP_VENDOR_SUBCMD_SET_NCI_CONFIG, 0, NULL);

	return r;
}

static int nxp_nci_set_proprietary_config(struct nfc_dev *dev, void *data,
					  size_t data_len)
{
	unsigned char i, fields;
	unsigned int data_index = 1;
	unsigned char* param = (unsigned char*) data;
	struct nxp_set_proprietary_config_param_hdr* param_hdr;
	int r;

	if (data_len < 1)
		return -EINVAL;

	fields = param[0];

	for (i = 0; i < fields; i++) {
		param_hdr = (struct nxp_set_proprietary_config_param_hdr*)
			&param[data_index];
		data_index +=
			sizeof(struct nxp_set_proprietary_config_param_hdr);
		if (data_index >= data_len)
			return -EINVAL;
		data_index += param_hdr->len;
	}

	if (data_index != data_len)
		return -EINVAL;

	r = nxp_nci_proprietary_cmd(dev, NCI_OP_CORE_SET_CONFIG_CMD,
				    data, data_len);

	nfc_vendor_rsp(dev, NXP_VENDOR_ID,
		       NXP_VENDOR_SUBCMD_SET_PROPRIETARY_CONFIG, 0, NULL);

	return r;
}

static int nxp_nci_get_nci_config(struct nfc_dev *dev, void *data,
				  size_t data_len)
{
	unsigned char fields;
	unsigned int data_index = 1;
	unsigned char* param = (unsigned char*) data;

	if (data_len < 1)
		return -EINVAL;

	fields = param[0];
	data_index += fields * sizeof(nxp_get_nci_config_param_hdr);

	if (data_index != data_len)
		return -EINVAL;

	return nxp_nci_proprietary_cmd(dev, NCI_OP_CORE_GET_CONFIG_CMD,
				       data, data_len);
}

static int nxp_nci_get_proprietary_config(struct nfc_dev *dev, void *data,
					  size_t data_len)
{
	unsigned char fields;
	unsigned int data_index = 1;
	unsigned char* param = (unsigned char*) data;

	if (data_len < 1)
		return -EINVAL;

	fields = param[0];
	data_index += fields * sizeof(nxp_get_proprietary_config_param_hdr);

	if (data_index != data_len)
		return -EINVAL;

	return nxp_nci_proprietary_cmd(dev, NCI_OP_CORE_GET_CONFIG_CMD,
				       data, data_len);
}

static int nxp_nci_enable_proprietary_extensions(struct nfc_dev *dev,
						 void *data, size_t data_len)
{
	if (data_len != 0)
		return -EINVAL;

	return nxp_nci_proprietary_cmd(dev,
		NCI_OP_PROPRIETARY_NXP_ENABLE_PROPRIETARY_EXTENSIONS_CMD,
		NULL, 0);
}

static int nxp_nci_antenna_selftest(struct nfc_dev *dev, void *data,
				    size_t data_len)
{
	unsigned char measurement_id;
	unsigned char* param = (unsigned char*) data;
	unsigned int header_len;

	if (data_len < 1)
		return -EINVAL;

	measurement_id = param[0];

	switch (measurement_id) {
	case NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_CURRENT:
		 header_len = 2;
		 break;
	case NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_AGC:
	case NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_AGC_FIXED_NFCLD:
	case NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_AGC_DIFF:
	case NXP_VENDOR_ANTENNA_SELFTEST_MEASUREMENT_RF_FIELD:
		 header_len = 4;
		 break;
	default:
		return -EINVAL;
	}

	if (data_len != header_len)
		return -EINVAL;

	return nxp_nci_proprietary_cmd(dev,
		NCI_OP_PROPRIETARY_NXP_ANTENNA_SELFTEST_CMD,
		data,
		data_len);
}

static struct nfc_vendor_cmd nxp_nci_vendor_cmds[] = {
	{
		.vendor_id = NXP_VENDOR_ID,
		.subcmd = NXP_VENDOR_SUBCMD_SET_NCI_CONFIG,
		.cmd = nxp_nci_set_nci_config
	},
	{
		.vendor_id = NXP_VENDOR_ID,
		.subcmd = NXP_VENDOR_SUBCMD_SET_PROPRIETARY_CONFIG,
		.cmd = nxp_nci_set_proprietary_config
	},
	{
		.vendor_id = NXP_VENDOR_ID,
		.subcmd = NXP_VENDOR_SUBCMD_GET_NCI_CONFIG,
		.cmd = nxp_nci_get_nci_config
	},
	{
		.vendor_id = NXP_VENDOR_ID,
		.subcmd = NXP_VENDOR_SUBCMD_GET_PROPRIETARY_CONFIG,
		.cmd = nxp_nci_get_proprietary_config
	},
	{
		.vendor_id = NXP_VENDOR_ID,
		.subcmd = NXP_VENDOR_SUBCMD_ENABLE_PROPRIETARY_EXTENSIONS,
		.cmd = nxp_nci_enable_proprietary_extensions
	},
	{
		.vendor_id = NXP_VENDOR_ID,
		.subcmd = NXP_VENDOR_SUBCMD_ANTENNA_SELFTEST,
		.cmd = nxp_nci_antenna_selftest
	},
};

int nxp_nci_probe(void *phy_id, struct device *pdev,
		  struct nxp_nci_phy_ops *phy_ops, unsigned int max_payload,
		  struct nci_dev **ndev)
{
	struct nxp_nci_info *info;
	int r;

	info = devm_kzalloc(pdev, sizeof(struct nxp_nci_info), GFP_KERNEL);
	if (!info) {
		r = -ENOMEM;
		goto probe_exit;
	}

	info->phy_id = phy_id;
	info->pdev = pdev;
	info->phy_ops = phy_ops;
	info->max_payload = max_payload;
	INIT_WORK(&info->fw_info.work, nxp_nci_fw_work);
	init_completion(&info->fw_info.cmd_completion);
	mutex_init(&info->info_lock);

	if (info->phy_ops->disable) {
		r = info->phy_ops->disable(info->phy_id);
		if (r < 0)
			goto probe_exit;
	}

	info->mode = NXP_NCI_MODE_COLD;

	info->ndev = nci_allocate_device(&nxp_nci_ops, NXP_NCI_NFC_PROTOCOLS,
					 NXP_NCI_HDR_LEN, 0);
	if (!info->ndev) {
		r = -ENOMEM;
		goto probe_exit;
	}

	nci_set_parent_dev(info->ndev, pdev);
	nci_set_drvdata(info->ndev, info);
	nci_set_vendor_cmds(info->ndev, nxp_nci_vendor_cmds,
			    __NXP_VENDOR_SUBCMD_AFTER_LAST);
	r = nci_register_device(info->ndev);
	if (r < 0)
		goto probe_exit_free_nci;

	*ndev = info->ndev;

	goto probe_exit;

probe_exit_free_nci:
	nci_free_device(info->ndev);
probe_exit:
	return r;
}
EXPORT_SYMBOL(nxp_nci_probe);

void nxp_nci_remove(struct nci_dev *ndev)
{
	struct nxp_nci_info *info = nci_get_drvdata(ndev);

	if (info->mode == NXP_NCI_MODE_FW)
		nxp_nci_fw_work_complete(info, -ESHUTDOWN);
	cancel_work_sync(&info->fw_info.work);

	mutex_lock(&info->info_lock);

	if (info->phy_ops->disable)
		info->phy_ops->disable(info->phy_id);

	nci_unregister_device(ndev);
	nci_free_device(ndev);

	mutex_unlock(&info->info_lock);
}
EXPORT_SYMBOL(nxp_nci_remove);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NXP NCI NFC driver");
MODULE_AUTHOR("Clément Perrochaud <clement.perrochaud@nxp.com>");
