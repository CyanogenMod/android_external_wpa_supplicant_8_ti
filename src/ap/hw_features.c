/*
 * hostapd / Hardware feature query and different modes
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2008-2012, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "drivers/driver.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "hw_features.h"


void hostapd_free_hw_features(struct hostapd_hw_modes *hw_features,
			      size_t num_hw_features)
{
	size_t i;

	if (hw_features == NULL)
		return;

	for (i = 0; i < num_hw_features; i++) {
		os_free(hw_features[i].channels);
		os_free(hw_features[i].rates);
	}

	os_free(hw_features);
}


int hostapd_get_hw_features(struct hostapd_iface *iface)
{
	struct hostapd_data *hapd = iface->bss[0];
	int ret = 0, i, j;
	u16 num_modes, flags;
	struct hostapd_hw_modes *modes;

	if (hostapd_drv_none(hapd))
		return -1;
	modes = hostapd_get_hw_feature_data(hapd, &num_modes, &flags);
	if (modes == NULL) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "Fetching hardware channel/rate support not "
			       "supported.");
		return -1;
	}

	iface->hw_flags = flags;

	hostapd_free_hw_features(iface->hw_features, iface->num_hw_features);
	iface->hw_features = modes;
	iface->num_hw_features = num_modes;

	for (i = 0; i < num_modes; i++) {
		struct hostapd_hw_modes *feature = &modes[i];
		/* set flag for channels we can use in current regulatory
		 * domain */
		for (j = 0; j < feature->num_channels; j++) {
			/*
			 * Disable all channels that are marked not to allow
			 * IBSS operation or active scanning. In addition,
			 * disable all channels that require radar detection,
			 * since that (in addition to full DFS) is not yet
			 * supported.
			 */
			if (feature->channels[j].flag &
			    (HOSTAPD_CHAN_NO_IBSS |
			     HOSTAPD_CHAN_PASSIVE_SCAN |
			     HOSTAPD_CHAN_RADAR))
				feature->channels[j].flag |=
					HOSTAPD_CHAN_DISABLED;
			if (feature->channels[j].flag & HOSTAPD_CHAN_DISABLED)
				continue;
			wpa_printf(MSG_MSGDUMP, "Allowed channel: mode=%d "
				   "chan=%d freq=%d MHz max_tx_power=%d dBm",
				   feature->mode,
				   feature->channels[j].chan,
				   feature->channels[j].freq,
				   feature->channels[j].max_tx_power);
		}
	}

	return ret;
}


int hostapd_prepare_rates(struct hostapd_iface *iface,
			  struct hostapd_hw_modes *mode)
{
	int i, num_basic_rates = 0;
	int basic_rates_a[] = { 60, 120, 240, -1 };
	int basic_rates_b[] = { 10, 20, -1 };
	int basic_rates_g[] = { 10, 20, 55, 110, -1 };
	int *basic_rates;

	if (iface->conf->basic_rates)
		basic_rates = iface->conf->basic_rates;
	else switch (mode->mode) {
	case HOSTAPD_MODE_IEEE80211A:
		basic_rates = basic_rates_a;
		break;
	case HOSTAPD_MODE_IEEE80211B:
		basic_rates = basic_rates_b;
		break;
	case HOSTAPD_MODE_IEEE80211G:
		basic_rates = basic_rates_g;
		break;
	default:
		return -1;
	}

	i = 0;
	while (basic_rates[i] >= 0)
		i++;
	if (i)
		i++; /* -1 termination */
	os_free(iface->basic_rates);
	iface->basic_rates = os_malloc(i * sizeof(int));
	if (iface->basic_rates)
		os_memcpy(iface->basic_rates, basic_rates, i * sizeof(int));

	os_free(iface->current_rates);
	iface->num_rates = 0;

	iface->current_rates =
		os_zalloc(mode->num_rates * sizeof(struct hostapd_rate_data));
	if (!iface->current_rates) {
		wpa_printf(MSG_ERROR, "Failed to allocate memory for rate "
			   "table.");
		return -1;
	}

	for (i = 0; i < mode->num_rates; i++) {
		struct hostapd_rate_data *rate;

		if (iface->conf->supported_rates &&
		    !hostapd_rate_found(iface->conf->supported_rates,
					mode->rates[i]))
			continue;

		rate = &iface->current_rates[iface->num_rates];
		rate->rate = mode->rates[i];
		if (hostapd_rate_found(basic_rates, rate->rate)) {
			rate->flags |= HOSTAPD_RATE_BASIC;
			num_basic_rates++;
		}
		wpa_printf(MSG_DEBUG, "RATE[%d] rate=%d flags=0x%x",
			   iface->num_rates, rate->rate, rate->flags);
		iface->num_rates++;
	}

	if ((iface->num_rates == 0 || num_basic_rates == 0) &&
	    (!iface->conf->ieee80211n || !iface->conf->require_ht)) {
		wpa_printf(MSG_ERROR, "No rates remaining in supported/basic "
			   "rate sets (%d,%d).",
			   iface->num_rates, num_basic_rates);
		return -1;
	}

	return 0;
}


#ifdef CONFIG_IEEE80211N
static int ieee80211n_allowed_ht40_channel_pair(struct hostapd_iface *iface)
{
	int sec_chan, ok, j, first;
	int allowed[] = { 36, 44, 52, 60, 100, 108, 116, 124, 132, 149, 157,
			  184, 192 };
	size_t k;

	if (!iface->conf->secondary_channel)
		return 1; /* HT40 not used */

	sec_chan = iface->conf->channel + iface->conf->secondary_channel * 4;
	wpa_printf(MSG_DEBUG, "HT40: control channel: %d  "
		   "secondary channel: %d",
		   iface->conf->channel, sec_chan);

	/* Verify that HT40 secondary channel is an allowed 20 MHz
	 * channel */
	ok = 0;
	for (j = 0; j < iface->current_mode->num_channels; j++) {
		struct hostapd_channel_data *chan =
			&iface->current_mode->channels[j];
		if (!(chan->flag & HOSTAPD_CHAN_DISABLED) &&
		    chan->chan == sec_chan) {
			ok = 1;
			break;
		}
	}
	if (!ok) {
		wpa_printf(MSG_ERROR, "HT40 secondary channel %d not allowed",
			   sec_chan);
		return 0;
	}

	/*
	 * Verify that HT40 primary,secondary channel pair is allowed per
	 * IEEE 802.11n Annex J. This is only needed for 5 GHz band since
	 * 2.4 GHz rules allow all cases where the secondary channel fits into
	 * the list of allowed channels (already checked above).
	 */
	if (iface->current_mode->mode != HOSTAPD_MODE_IEEE80211A)
		return 1;

	if (iface->conf->secondary_channel > 0)
		first = iface->conf->channel;
	else
		first = sec_chan;

	ok = 0;
	for (k = 0; k < sizeof(allowed) / sizeof(allowed[0]); k++) {
		if (first == allowed[k]) {
			ok = 1;
			break;
		}
	}
	if (!ok) {
		wpa_printf(MSG_ERROR, "HT40 channel pair (%d, %d) not allowed",
			   iface->conf->channel,
			   iface->conf->secondary_channel);
		return 0;
	}

	return 1;
}


static void ieee80211n_switch_pri_sec(struct hostapd_iface *iface)
{
	if (iface->conf->secondary_channel > 0) {
		iface->conf->channel += 4;
		iface->conf->secondary_channel = -1;
	} else {
		iface->conf->channel -= 4;
		iface->conf->secondary_channel = 1;
	}
}


static void ieee80211n_get_pri_sec_chan(struct wpa_scan_res *bss,
					int *pri_chan, int *sec_chan)
{
	struct ieee80211_ht_operation *oper;
	struct ieee802_11_elems elems;

	*pri_chan = *sec_chan = 0;

	ieee802_11_parse_elems((u8 *) (bss + 1), bss->ie_len, &elems, 0);
	if (elems.ht_operation &&
	    elems.ht_operation_len >= sizeof(*oper)) {
		oper = (struct ieee80211_ht_operation *) elems.ht_operation;
		*pri_chan = oper->control_chan;
		if (oper->ht_param & HT_INFO_HT_PARAM_REC_TRANS_CHNL_WIDTH) {
			int sec = oper->ht_param &
				HT_INFO_HT_PARAM_SECONDARY_CHNL_OFF_MASK;
			if (sec == HT_INFO_HT_PARAM_SECONDARY_CHNL_ABOVE)
				*sec_chan = *pri_chan + 4;
			else if (sec == HT_INFO_HT_PARAM_SECONDARY_CHNL_BELOW)
				*sec_chan = *pri_chan - 4;
		}
	}
}


static int ieee80211n_check_40mhz_5g(struct hostapd_iface *iface,
				     struct wpa_scan_results *scan_res)
{
	int pri_chan, sec_chan, pri_freq, sec_freq, pri_bss, sec_bss;
	int bss_pri_chan, bss_sec_chan;
	size_t i;
	int match;

	pri_chan = iface->conf->channel;
	sec_chan = iface->conf->secondary_channel * 4;
	pri_freq = hostapd_hw_get_freq(iface->bss[0], pri_chan);
	if (iface->conf->secondary_channel > 0)
		sec_freq = pri_freq + 20;
	else
		sec_freq = pri_freq - 20;

	/*
	 * Switch PRI/SEC channels if Beacons were detected on selected SEC
	 * channel, but not on selected PRI channel.
	 */
	pri_bss = sec_bss = 0;
	for (i = 0; i < scan_res->num; i++) {
		struct wpa_scan_res *bss = scan_res->res[i];
		if (bss->freq == pri_freq)
			pri_bss++;
		else if (bss->freq == sec_freq)
			sec_bss++;
	}
	if (sec_bss && !pri_bss) {
		wpa_printf(MSG_INFO, "Switch own primary and secondary "
			   "channel to get secondary channel with no Beacons "
			   "from other BSSes");
		ieee80211n_switch_pri_sec(iface);
	}

	/*
	 * Match PRI/SEC channel with any existing HT40 BSS on the same
	 * channels that we are about to use (if already mixed order in
	 * existing BSSes, use own preference).
	 */
	match = 0;
	for (i = 0; i < scan_res->num; i++) {
		struct wpa_scan_res *bss = scan_res->res[i];
		ieee80211n_get_pri_sec_chan(bss, &bss_pri_chan, &bss_sec_chan);
		if (pri_chan == bss_pri_chan &&
		    sec_chan == bss_sec_chan) {
			match = 1;
			break;
		}
	}
	if (!match) {
		for (i = 0; i < scan_res->num; i++) {
			struct wpa_scan_res *bss = scan_res->res[i];
			ieee80211n_get_pri_sec_chan(bss, &bss_pri_chan,
						    &bss_sec_chan);
			if (pri_chan == bss_sec_chan &&
			    sec_chan == bss_pri_chan) {
				wpa_printf(MSG_INFO, "Switch own primary and "
					   "secondary channel due to BSS "
					   "overlap with " MACSTR,
					   MAC2STR(bss->bssid));
				ieee80211n_switch_pri_sec(iface);
				break;
			}
		}
	}

	return 1;
}


static int ieee80211n_check_40mhz_2g4(struct hostapd_iface *iface,
				      struct wpa_scan_results *scan_res)
{
	int pri_freq, sec_freq;
	int affected_start, affected_end;
	size_t i;

	pri_freq = hostapd_hw_get_freq(iface->bss[0], iface->conf->channel);
	if (iface->conf->secondary_channel > 0)
		sec_freq = pri_freq + 20;
	else
		sec_freq = pri_freq - 20;
	affected_start = (pri_freq + sec_freq) / 2 - 25;
	affected_end = (pri_freq + sec_freq) / 2 + 25;
	wpa_printf(MSG_DEBUG, "40 MHz affected channel range: [%d,%d] MHz",
		   affected_start, affected_end);
	for (i = 0; i < scan_res->num; i++) {
		struct wpa_scan_res *bss = scan_res->res[i];
		int pri = bss->freq;
		int sec = pri;
		int sec_chan, pri_chan;

		ieee80211n_get_pri_sec_chan(bss, &pri_chan, &sec_chan);

		if (sec_chan) {
			if (sec_chan < pri_chan)
				sec = pri - 20;
			else
				sec = pri + 20;
		}

		if ((pri < affected_start || pri > affected_end) &&
		    (sec < affected_start || sec > affected_end))
			continue; /* not within affected channel range */

		wpa_printf(MSG_DEBUG, "Neighboring BSS: " MACSTR
			   " freq=%d pri=%d sec=%d",
			   MAC2STR(bss->bssid), bss->freq, pri_chan, sec_chan);

		if (sec_chan) {
			if (pri_freq != pri || sec_freq != sec) {
				wpa_printf(MSG_DEBUG, "40 MHz pri/sec "
					   "mismatch with BSS " MACSTR
					   " <%d,%d> (chan=%d%c) vs. <%d,%d>",
					   MAC2STR(bss->bssid),
					   pri, sec, pri_chan,
					   sec > pri ? '+' : '-',
					   pri_freq, sec_freq);
				return 0;
			}
		}

		/* TODO: 40 MHz intolerant */
	}

	return 1;
}


static int ieee80211n_check_scan(struct hostapd_iface *iface,
				 struct wpa_scan_results *scan_res)
{
	int oper40;
	int res;

	if (iface->current_mode->mode == HOSTAPD_MODE_IEEE80211A)
		oper40 = ieee80211n_check_40mhz_5g(iface, scan_res);
	else
		oper40 = ieee80211n_check_40mhz_2g4(iface, scan_res);

	if (!oper40) {
		wpa_printf(MSG_INFO, "20/40 MHz operation not permitted on "
			   "channel pri=%d sec=%d based on overlapping BSSes",
			   iface->conf->channel,
			   iface->conf->channel +
			   iface->conf->secondary_channel * 4);
		iface->conf->secondary_channel = 0;
		iface->conf->ht_capab &= ~HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
	}

	res = ieee80211n_allowed_ht40_channel_pair(iface);
	hostapd_setup_interface_complete(iface, !res);
	return 1;
}


static void ieee80211n_get_res_and_check_scan(struct hostapd_iface *iface)
{
	struct wpa_scan_results *scan_res;

	/* Check list of neighboring BSSes (from scan) to see whether 40 MHz is
	 * allowed per IEEE Std 802.11-2012, 10.15.3.2 */

	iface->scan_cb = NULL;

	scan_res = hostapd_driver_get_scan_results(iface->bss[0]);
	if (scan_res == NULL) {
		hostapd_setup_interface_complete(iface, 1);
		return;
	}

	ieee80211n_check_scan(iface, scan_res);
	wpa_scan_results_free(scan_res);
}


static void ieee80211n_scan_channels_2g4(struct hostapd_iface *iface,
					 struct wpa_driver_scan_params *params)
{
	/* Scan only the affected frequency range */
	int pri_freq, sec_freq;
	int affected_start, affected_end;
	int i, pos;
	struct hostapd_hw_modes *mode;

	if (iface->current_mode == NULL)
		return;

	pri_freq = hostapd_hw_get_freq(iface->bss[0], iface->conf->channel);
	if (iface->conf->secondary_channel > 0)
		sec_freq = pri_freq + 20;
	else
		sec_freq = pri_freq - 20;
	affected_start = (pri_freq + sec_freq) / 2 - 25;
	affected_end = (pri_freq + sec_freq) / 2 + 25;
	wpa_printf(MSG_DEBUG, "40 MHz affected channel range: [%d,%d] MHz",
		   affected_start, affected_end);

	mode = iface->current_mode;
	params->freqs = os_zalloc((mode->num_channels + 1) * sizeof(int));
	if (params->freqs == NULL)
		return;
	pos = 0;

	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *chan = &mode->channels[i];
		if (chan->flag & HOSTAPD_CHAN_DISABLED)
			continue;
		if (chan->freq < affected_start ||
		    chan->freq > affected_end)
			continue;
		params->freqs[pos++] = chan->freq;
	}
}


static int ieee80211n_check_40mhz(struct hostapd_iface *iface)
{
	struct wpa_driver_scan_params params;

	if (!iface->conf->secondary_channel)
		return 0; /* HT40 not used */

	wpa_printf(MSG_DEBUG, "Scan for neighboring BSSes prior to enabling "
		   "40 MHz channel");
	os_memset(&params, 0, sizeof(params));
	if (iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G)
		ieee80211n_scan_channels_2g4(iface, &params);
	if (hostapd_driver_scan(iface->bss[0], &params) < 0) {
		wpa_printf(MSG_ERROR, "Failed to request a scan of "
			   "neighboring BSSes");
		os_free(params.freqs);
		return -1;
	}
	os_free(params.freqs);

	iface->scan_cb = ieee80211n_get_res_and_check_scan;
	return 1;
}


static int ieee80211n_supported_ht_capab(struct hostapd_iface *iface)
{
	u16 hw = iface->current_mode->ht_capab;
	u16 conf = iface->conf->ht_capab;

	if ((conf & HT_CAP_INFO_LDPC_CODING_CAP) &&
	    !(hw & HT_CAP_INFO_LDPC_CODING_CAP)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [LDPC]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET) &&
	    !(hw & HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [HT40*]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_SMPS_MASK) != (hw & HT_CAP_INFO_SMPS_MASK) &&
	    (conf & HT_CAP_INFO_SMPS_MASK) != HT_CAP_INFO_SMPS_DISABLED) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [SMPS-*]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_GREEN_FIELD) &&
	    !(hw & HT_CAP_INFO_GREEN_FIELD)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [GF]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_SHORT_GI20MHZ) &&
	    !(hw & HT_CAP_INFO_SHORT_GI20MHZ)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [SHORT-GI-20]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_SHORT_GI40MHZ) &&
	    !(hw & HT_CAP_INFO_SHORT_GI40MHZ)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [SHORT-GI-40]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_TX_STBC) && !(hw & HT_CAP_INFO_TX_STBC)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [TX-STBC]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_RX_STBC_MASK) >
	    (hw & HT_CAP_INFO_RX_STBC_MASK)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [RX-STBC*]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_DELAYED_BA) &&
	    !(hw & HT_CAP_INFO_DELAYED_BA)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [DELAYED-BA]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_MAX_AMSDU_SIZE) &&
	    !(hw & HT_CAP_INFO_MAX_AMSDU_SIZE)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [MAX-AMSDU-7935]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_DSSS_CCK40MHZ) &&
	    !(hw & HT_CAP_INFO_DSSS_CCK40MHZ)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [DSSS_CCK-40]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_PSMP_SUPP) && !(hw & HT_CAP_INFO_PSMP_SUPP)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [PSMP]");
		return 0;
	}

	if ((conf & HT_CAP_INFO_LSIG_TXOP_PROTECT_SUPPORT) &&
	    !(hw & HT_CAP_INFO_LSIG_TXOP_PROTECT_SUPPORT)) {
		wpa_printf(MSG_ERROR, "Driver does not support configured "
			   "HT capability [LSIG-TXOP-PROT]");
		return 0;
	}

	return 1;
}

#endif /* CONFIG_IEEE80211N */


int hostapd_check_ht_capab(struct hostapd_iface *iface,
			   struct wpa_scan_results *scan_res)
{
#ifdef CONFIG_IEEE80211N
	int ret;
	if (!iface->conf->ieee80211n)
		return 0;
	if (!ieee80211n_supported_ht_capab(iface))
		return -1;
	if (scan_res)
		ret = ieee80211n_check_scan(iface, scan_res);
	else
		ret = ieee80211n_check_40mhz(iface);

	/* sometimes the init should proceed async or fail */
	if (ret)
		return ret;
	if (!ieee80211n_allowed_ht40_channel_pair(iface))
		return -1;
#endif /* CONFIG_IEEE80211N */

	return 0;
}


static int valid_ap_channel(struct hostapd_iface *iface, int chan)
{
	int j;
	struct hostapd_channel_data *c;
	int *list;

	/* don't allow AP on channel 14 - only JP 11b rates */
	if (chan == 14)
		return 0;

	/* don't allow channels on the the ACS blacklist */
	if (iface->conf->acs_blacklist) {
		list = iface->conf->acs_blacklist;
		for (j = 0; list[j] >= 0; j++)
			if (chan == list[j])
				return 0;
	}

	/* only allow channels from the ACS whitelist */
	if (iface->conf->acs_whitelist) {
		list = iface->conf->acs_whitelist;
		for (j = 0; list[j] >= 0; j++)
			if (chan == list[j])
				break;

		/* channel not found */
		if (list[j] != chan)
			return 0;
	}

	for (j = 0; j < iface->current_mode->num_channels; j++) {
		c = &iface->current_mode->channels[j];
		if (c->chan == chan)
			return (c->flag & HOSTAPD_CHAN_DISABLED) ? 0 : 1;
	}

	/* channel not found */
	return 0;
}


struct oper_class_map {
	enum hostapd_hw_mode mode;
	u8 op_class;
	u8 min_chan;
	u8 max_chan;
	u8 inc;
	enum { BW40PLUS, BW40MINUS } bw;
};

/* this is a duplication of the table in p2p_supplicant.c.
 * all changes here must be propagated there and vice versa */
static struct oper_class_map op_class[] = {
#if 0 /* diallow HT40 on 2.4Ghz on purpose */
	{ HOSTAPD_MODE_IEEE80211G, 83, 1, 9, 1, BW40PLUS },
	{ HOSTAPD_MODE_IEEE80211G, 84, 5, 13, 1, BW40MINUS },
#endif
	{ HOSTAPD_MODE_IEEE80211A, 116, 36, 44, 8, BW40PLUS },
	{ HOSTAPD_MODE_IEEE80211A, 117, 40, 48, 8, BW40MINUS },
	{ HOSTAPD_MODE_IEEE80211A, 126, 149, 157, 8, BW40PLUS },
	{ HOSTAPD_MODE_IEEE80211A, 127, 153, 161, 8, BW40MINUS },
	{ -1, 0, 0, 0, 0, BW40PLUS } /* terminator */
};

static int channel_distance(struct hostapd_iface *iface)
{
	switch (iface->current_mode->mode) {
	case HOSTAPD_MODE_IEEE80211A:
		return 4;
	case HOSTAPD_MODE_IEEE80211B:
	case HOSTAPD_MODE_IEEE80211G:
		return 1;
	default:
		break;
	}

	wpa_printf(MSG_ERROR, "Invalid HW mode for channel distance");
	return 0;
}



/* Returns secondary channel (-1, 1), if possible considering the
 * user preferred secondary channel. If no HT40 operation is possible,
 * returns 0 */
static int select_secondary_channel(struct hostapd_iface *iface,
				    int primary_chan, int pref_sec_chan)
{
	int i;
	int up_ok = 0, down_ok = 0;

	for (i = 0; op_class[i].op_class; i++) {
		struct oper_class_map *o = &op_class[i];
		u8 ch;

		if (o->mode != iface->current_mode->mode)
			continue;

		if (primary_chan < o->min_chan || primary_chan > o->max_chan)
			continue;

		for (ch = o->min_chan; ch <= o->max_chan; ch += o->inc) {
			if (ch == primary_chan) {
				if (o->bw == BW40PLUS)
					up_ok = 1;
				else if (o->bw == BW40MINUS)
					down_ok = 1;

				break;
			}
		}
	}

	if (up_ok && !valid_ap_channel(iface,
				primary_chan + channel_distance(iface)))
		up_ok = 0;
	if (down_ok && !valid_ap_channel(iface,
				primary_chan - channel_distance(iface)))
		down_ok = 0;

	if ((pref_sec_chan == 1 && up_ok) || (pref_sec_chan == -1 && down_ok))
		return pref_sec_chan;

	if (up_ok)
		return 1;
	else if (down_ok)
		return -1;

	/* no secondary channel possible */
	return 0;
}

/* unreasonable number of APs to find on a channel. */
#define MAX_AP_COUNT 10000

void set_prim_sec_chan(struct hostapd_iface *iface, int *channel_cnt,
		       int min_cnt, int default_prim_chan)
{
	int j, i;
	int min_sec_cnt = MAX_AP_COUNT, min_sec_prim_chan = -1,
		min_sec_chan_dir = -1;
	int prim_chan, sec_chan_dir, sec_chan;

	if (!iface->conf->secondary_channel)
		goto set;

	/* if a secondary channel is requested, try to select a channel that
	 * allows HT40 from the minimal AP ones */
	for (j = 0; j < iface->current_mode->num_channels; j++) {
		prim_chan = iface->current_mode->channels[j].chan;
		if (channel_cnt[j] != min_cnt)
			continue;

		sec_chan_dir = select_secondary_channel(iface, prim_chan,
					iface->conf->secondary_channel);
		if (!sec_chan_dir)
			continue;

		/* see if this secondary channel has minimal APs count */
		sec_chan = prim_chan + sec_chan_dir * channel_distance(iface);
		for (i = 0; i < iface->current_mode->num_channels; i++) {
			if (iface->current_mode->channels[i].chan == sec_chan)
				break;
		}

		if (i < iface->current_mode->num_channels &&
		    channel_cnt[i] < min_sec_cnt) {
			min_sec_cnt = channel_cnt[i];
			min_sec_prim_chan = prim_chan;
			min_sec_chan_dir = sec_chan_dir;
		}
	}

	/* found some sec chan with minimal APs */
	if (min_sec_cnt != MAX_AP_COUNT) {
		iface->conf->channel = min_sec_prim_chan;
		iface->conf->secondary_channel = min_sec_chan_dir;
		return;
	}

	wpa_printf(MSG_DEBUG, "Could not auto-select secondary channel");

set:
	iface->conf->channel = default_prim_chan;
	iface->conf->secondary_channel = 0;
}


static void hostapd_auto_select_scan_cb(struct hostapd_iface *iface)
{
	struct wpa_scan_results *scan_res;
	size_t i, j;
	int *channel_cnt;
	int min_cnt, min_idx;
	struct hostapd_channel_data *chan;

	iface->scan_cb = NULL;

	/* init all channel counters to 0 */
	channel_cnt = os_zalloc(iface->current_mode->num_channels * sizeof(int));
	if (channel_cnt == NULL) {
		hostapd_setup_interface_complete(iface, 1);
		return;
	}

	scan_res = hostapd_driver_get_scan_results(iface->bss[0]);
	if (scan_res == NULL) {
		hostapd_setup_interface_complete(iface, 1);
		goto free_chans;
	}

	/* increment channel counters according to scan results */
	for (i = 0; i < scan_res->num; i++) {
		struct wpa_scan_res *bss = scan_res->res[i];
		for (j = 0; j < iface->current_mode->num_channels; j++) {
			chan = &iface->current_mode->channels[j];
			if (bss->freq == chan->freq) {
				channel_cnt[j]++;
				wpa_printf(MSG_MSGDUMP, "%d BSSes on ch %d",
					   channel_cnt[j], chan->chan);
				break;
			}
		}
	}

	min_idx = -1;
	min_cnt = MAX_AP_COUNT;
	for (j = 0; j < iface->current_mode->num_channels; j++) {
		chan = &iface->current_mode->channels[j];
		if (!valid_ap_channel(iface, chan->chan)) {
			channel_cnt[j] = MAX_AP_COUNT;
			continue;
		}

		if (channel_cnt[j] >= min_cnt)
			continue;

		min_cnt = channel_cnt[j];
		min_idx = j;
	}

	if (min_idx == -1) {
		wpa_printf(MSG_ERROR,
			   "Could not select channel automatically");
		hostapd_setup_interface_complete(iface, 1);
		goto free_scan;
	}

	chan = &iface->current_mode->channels[min_idx];
	wpa_printf(MSG_DEBUG, "Min APs found in channel %d (AP count %d)",
		   chan->chan, min_cnt);

	/* Select a secondary channel and fine tune the primary one.
	 * Basically we try to start HT40, without increasing the number
	 * of APs on the primary channel. */
	set_prim_sec_chan(iface, channel_cnt, min_cnt, chan->chan);

	wpa_printf(MSG_DEBUG, "Auto-selected channel: %d secondary: %d",
		   iface->conf->channel, iface->conf->secondary_channel);

	/* will complete interface setup */
	hostapd_check_ht_capab(iface, scan_res);

free_scan:
	wpa_scan_results_free(scan_res);

free_chans:
	os_free(channel_cnt);
}


static int hostapd_auto_select_channel(struct hostapd_iface *iface)
{
	struct wpa_driver_scan_params params;

	/* TODO: we can scan only the current HW mode */
	wpa_printf(MSG_DEBUG, "Scan for neighboring BSSes to select channel");
	os_memset(&params, 0, sizeof(params));
	if (hostapd_driver_scan(iface->bss[0], &params) < 0) {
		wpa_printf(MSG_ERROR, "Failed to request a scan of "
			   "neighboring BSSes");
		return -1;
	}

	iface->scan_cb = hostapd_auto_select_scan_cb;
	return 0;
}


/**
 * hostapd_select_hw_mode - Select the hardware mode
 * @iface: Pointer to interface data.
 * Returns: 0 on success, < 0 on failure
 *
 * Sets up the hardware mode, channel, rates, and passive scanning
 * based on the configuration.
 */
int hostapd_select_hw_mode(struct hostapd_iface *iface)
{
	int i, j, ok;

	if (iface->num_hw_features < 1)
		return -1;

	iface->current_mode = NULL;
	for (i = 0; i < iface->num_hw_features; i++) {
		struct hostapd_hw_modes *mode = &iface->hw_features[i];
		if (mode->mode == iface->conf->hw_mode) {
			iface->current_mode = mode;
			break;
		}
	}

	if (iface->current_mode == NULL) {
		wpa_printf(MSG_ERROR, "Hardware does not support configured "
			   "mode");
		hostapd_logger(iface->bss[0], NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "Hardware does not support configured mode "
			       "(%d) (hw_mode in hostapd.conf)",
			       (int) iface->conf->hw_mode);
		return -2;
	}

	/*
	 * request a scan of neighboring BSSes and select the
	 * channel automatically
	 */
	if (iface->conf->channel == 0) {
		if (hostapd_auto_select_channel(iface)) {
			wpa_printf(MSG_ERROR, "Channel not configured "
				   "(hw_mode/channel in hostapd.conf) and "
				   "automatic channel selection failed");
			return -3;
		} else {
			wpa_printf(MSG_DEBUG, "Operating channel will be "
				   "selected automatically");
			/* will be completed async */
			return 1;
		}
	}

	ok = 0;
	for (j = 0; j < iface->current_mode->num_channels; j++) {
		struct hostapd_channel_data *chan =
			&iface->current_mode->channels[j];
		if (chan->chan == iface->conf->channel) {
			if (chan->flag & HOSTAPD_CHAN_DISABLED) {
				wpa_printf(MSG_ERROR,
					   "channel [%i] (%i) is disabled for "
					   "use in AP mode, flags: 0x%x%s%s%s",
					   j, chan->chan, chan->flag,
					   chan->flag & HOSTAPD_CHAN_NO_IBSS ?
					   " NO-IBSS" : "",
					   chan->flag &
					   HOSTAPD_CHAN_PASSIVE_SCAN ?
					   " PASSIVE-SCAN" : "",
					   chan->flag & HOSTAPD_CHAN_RADAR ?
					   " RADAR" : "");
			} else {
				ok = 1;
				break;
			}
		}
	}
	if (ok && iface->conf->secondary_channel) {
		int sec_ok = 0;
		int sec_chan = iface->conf->channel +
			iface->conf->secondary_channel * 4;
		for (j = 0; j < iface->current_mode->num_channels; j++) {
			struct hostapd_channel_data *chan =
				&iface->current_mode->channels[j];
			if (!(chan->flag & HOSTAPD_CHAN_DISABLED) &&
			    (chan->chan == sec_chan)) {
				sec_ok = 1;
				break;
			}
		}
		if (!sec_ok) {
			hostapd_logger(iface->bss[0], NULL,
				       HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_WARNING,
				       "Configured HT40 secondary channel "
				       "(%d) not found from the channel list "
				       "of current mode (%d) %s",
				       sec_chan, iface->current_mode->mode,
				       hostapd_hw_mode_txt(
					       iface->current_mode->mode));
			ok = 0;
		}
	}

	if (ok == 0) {
		hostapd_logger(iface->bss[0], NULL,
			       HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "Configured channel (%d) not found from the "
			       "channel list of current mode (%d) %s",
			       iface->conf->channel,
			       iface->current_mode->mode,
			       hostapd_hw_mode_txt(iface->current_mode->mode));
		iface->current_mode = NULL;
	}

	if (iface->current_mode == NULL) {
		hostapd_logger(iface->bss[0], NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_WARNING,
			       "Hardware does not support configured channel");
		return -4;
	}

	return 0;
}


const char * hostapd_hw_mode_txt(int mode)
{
	switch (mode) {
	case HOSTAPD_MODE_IEEE80211A:
		return "IEEE 802.11a";
	case HOSTAPD_MODE_IEEE80211B:
		return "IEEE 802.11b";
	case HOSTAPD_MODE_IEEE80211G:
		return "IEEE 802.11g";
	default:
		return "UNKNOWN";
	}
}


int hostapd_hw_get_freq(struct hostapd_data *hapd, int chan)
{
	int i;

	if (!hapd->iface->current_mode)
		return 0;

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		struct hostapd_channel_data *ch =
			&hapd->iface->current_mode->channels[i];
		if (ch->chan == chan)
			return ch->freq;
	}

	return 0;
}


int hostapd_hw_get_channel(struct hostapd_data *hapd, int freq)
{
	int i;

	if (!hapd->iface->current_mode)
		return 0;

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		struct hostapd_channel_data *ch =
			&hapd->iface->current_mode->channels[i];
		if (ch->freq == freq)
			return ch->chan;
	}

	return 0;
}


int hostapd_hw_get_channel_flag(struct hostapd_data *hapd, int chan)
{
	int i;

	if (!hapd->iface->current_mode)
		return 0;

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		struct hostapd_channel_data *ch =
			&hapd->iface->current_mode->channels[i];
		if (ch->chan == chan)
			return ch->flag;
	}

	return 0;
}
