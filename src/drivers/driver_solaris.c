#include "includes.h"
#include "common.h"
#include "driver.h"
#include "common/ieee802_11_defs.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <door.h>
#include <inet/wifi_ioctl.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libdllink.h>
#include "libdlwlan.h"

#define     WPA_STATUS(status)      (status == DLADM_STATUS_OK? 0 : -1)
#define     WPA_DOOR                "/var/run/wpa_door"

typedef enum {
    SOLARIS_EVENT_ASSOC,
    SOLARIS_EVENT_DISASSOC,
    SOLARIS_EVENT_SCAN_RESULTS
} solaris_wpa_event_type;

typedef struct wl_events {
    solaris_wpa_event_type event;
} wl_events_t;

typedef struct {
    char door_file[MAXPATHLEN];
    int door_id;
    dlpi_handle_t dh;
    dladm_handle_t handle;
    datalink_id_t linkid;
    struct wpa_scan_results results;
} wpa_driver_solaris_data;

static int
wpa_driver_solaris_set_wpa_ie(void *priv, const uint8_t *wpa_ie, const uint32_t wpa_ie_len)
{
    dladm_status_t status;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "%s", "wpa_driver_solaris_set_wpa_ie");
    status = dladm_wlan_wpa_set_ie(data->handle, data->linkid, (uint8_t*) wpa_ie, (uint32_t) wpa_ie_len);

    return (WPA_STATUS(status));
}

static int
wpa_driver_solaris_set_wpa(void *priv, boolean_t enabled)
{
    dladm_status_t status;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_set_wpa: enable=%d", enabled);

    if (!enabled && wpa_driver_solaris_set_wpa_ie(priv, NULL, 0) < 0)
        return (-1);

    status = dladm_wlan_wpa_set_wpa(data->handle, data->linkid, enabled);

    return (WPA_STATUS(status));
}

static void
wpa_driver_solaris_event_handler(void *cookie, char *argp, size_t asize,
    door_desc_t *dp, uint_t n_desc)
{
    solaris_wpa_event_type event;

    /* LINTED E_BAD_PTR_CAST_ALIGN */
    event = ((wl_events_t *)argp)->event;
    
    switch (event) {
    case SOLARIS_EVENT_ASSOC:
        wpa_supplicant_event(cookie, EVENT_ASSOC, NULL);
        break;
    case SOLARIS_EVENT_DISASSOC:
        wpa_supplicant_event(cookie, EVENT_DISASSOC, NULL);
        break;
    case SOLARIS_EVENT_SCAN_RESULTS:
        wpa_supplicant_event(cookie, EVENT_SCAN_RESULTS, NULL);
        break;
    default:
        wpa_printf(MSG_DEBUG, "wpa_driver_solaris_event_handler: invalid event %d", event);
        break;
    }

    (void) door_return(NULL, 0, NULL, 0);
}

/*
 * Create the driver to wpad door
 */
static int
wpa_driver_solaris_door_setup(wpa_driver_solaris_data *data, void *cookie)
{
    struct stat stbuf;
    int error = 0;

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_door_setup(%s)", data->door_file);
    /*
     * Create the door
     */
    data->door_id = door_create(wpa_driver_solaris_event_handler, cookie,
        DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL);

    if (data->door_id < 0) {
        error = -1;
        goto out;
    }

    if (stat(data->door_file, &stbuf) < 0) {
        int newfd;
        if ((newfd = creat(data->door_file, 0666)) < 0) {
            (void) door_revoke(data->door_id);
            data->door_id = -1;
            error = -1;

            goto out;
        }
        (void) close(newfd);
    }

    if (fattach(data->door_id, data->door_file) < 0) {
        if ((errno != EBUSY) || (fdetach(data->door_file) < 0) ||
            (fattach(data->door_id, data->door_file) < 0)) {
            (void) door_revoke(data->door_id);
            data->door_id = -1;
            error = -1;

            goto out;
        }
    }

out:
    return (error);
}

static void
wpa_driver_solaris_door_destroy(wpa_driver_solaris_data *data)
{
    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_door_destroy(%s)\n", data->door_file);

    if (data->door_id == -1)
        return;

    if (door_revoke(data->door_id) == -1) {
        wpa_printf(MSG_ERROR, "failed to door_revoke(%d) %s, exiting.",
            data->door_id, strerror(errno));
    }

    if (fdetach(data->door_file) == -1) {
        wpa_printf(MSG_ERROR, "failed to fdetach %s: %s, exiting.",
            data->door_file, strerror(errno));
    }

    (void) close(data->door_id);
}

void*
wpa_driver_solaris_init(void *ctx, const char *ifname)
{
    wpa_driver_solaris_data *data;
    dladm_phys_attr_t dpa;

    /* TODO: Check for error */
    data = (wpa_driver_solaris_data*) os_zalloc(sizeof(wpa_driver_solaris_data));

    /*
     * Hold this link open to prevent a link renaming operation.
     */
    if (dlpi_open(ifname, &data->dh, 0) != DLPI_SUCCESS) {
        wpa_printf(MSG_ERROR, "Failed to open link '%s'.", ifname);
        return NULL;
    }

    /* This handle is stored in wpa_s when that struct is filled. */
    if (dladm_open(&data->handle) != DLADM_STATUS_OK) {
        wpa_printf(MSG_ERROR, "Failed to open dladm handle");
        dlpi_close(data->dh);
        return NULL;
    }

    if (dladm_name2info(data->handle, ifname, &data->linkid, NULL, NULL, NULL) !=
        DLADM_STATUS_OK) {
        wpa_printf(MSG_ERROR, "Invalid link name '%s'.", ifname);
        dladm_close(data->handle);
        dlpi_close(data->dh);
        return NULL;
    }

    /*
     * Get the device name of the link, which will be used as the door
     * file name used to communicate with the driver. Note that different
     * links use different doors.
     */
    if (dladm_phys_info(data->handle, data->linkid, &dpa, DLADM_OPT_ACTIVE) !=
        DLADM_STATUS_OK) {
        wpa_printf(MSG_ERROR,
            "Failed to get device name of link '%s'.", link);
        dladm_close(data->handle);
        dlpi_close(data->dh);
        return NULL;
    }
    (void) snprintf(data->door_file, MAXPATHLEN, "%s_%s", WPA_DOOR, dpa.dp_dev);

    /*
     * Setup door file to communicate with driver
     */
    data->door_id = 0;
    if (wpa_driver_solaris_door_setup(data, ctx) != 0) {
        wpa_printf(MSG_ERROR, "Failed to setup door(%s)", data->door_file);
        dladm_close(data->handle);
        dlpi_close(data->dh);
        return NULL;
    }

    if (wpa_driver_solaris_set_wpa(data, 1) < 0) {
        wpa_printf(MSG_ERROR, "Failed to enable WPA in the driver.");
        wpa_driver_solaris_door_destroy(data);
        dladm_close(data->handle);
        dlpi_close(data->dh);
        return NULL;
    }

    return data;
}

void
wpa_driver_solaris_deinit(void *priv)
{
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;
    
    if (wpa_driver_solaris_set_wpa(data, 0) < 0) {
        wpa_printf(MSG_ERROR, "Failed to disable WPA in the driver.");
    }
    
    wpa_driver_solaris_door_destroy(data);
    dladm_close(data->handle);
    dlpi_close(data->dh);
    os_free(data);
}

int
wpa_driver_solaris_get_bssid(void *priv, u8 *bssid)
{
    dladm_status_t status;
    dladm_wlan_linkattr_t attr;
    dladm_wlan_attr_t *wl_attrp;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    status = dladm_wlan_get_linkattr(data->handle, data->linkid, &attr);
    if (status != DLADM_STATUS_OK)
        return (-1);

    wl_attrp = &attr.la_wlan_attr;
    if ((attr.la_valid & DLADM_WLAN_LINKATTR_WLAN) == 0 ||
        (wl_attrp->wa_valid & DLADM_WLAN_ATTR_BSSID) == 0)
        return (-1);

    (void) memcpy(bssid, wl_attrp->wa_bssid.wb_bytes, DLADM_WLAN_BSSID_LEN);

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_get_bssid: " MACSTR,
        MAC2STR((unsigned char *)bssid));

    return (WPA_STATUS(status));
}

int
wpa_driver_solaris_get_ssid(void *priv, u8 *ssid)
{
    int ret;
    dladm_status_t status;
    dladm_wlan_linkattr_t attr;
    dladm_wlan_attr_t *wl_attrp;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    status = dladm_wlan_get_linkattr(data->handle, data->linkid, &attr);
    if (status != DLADM_STATUS_OK)
        return (-1);

    wl_attrp = &attr.la_wlan_attr;
    if ((attr.la_valid & DLADM_WLAN_LINKATTR_WLAN) == 0 ||
        (wl_attrp->wa_valid & DLADM_WLAN_ATTR_ESSID) == 0)
        return (-1);

    (void) memcpy(ssid, wl_attrp->wa_essid.we_bytes, MAX_ESSID_LENGTH);
    ret = strlen((const char*) ssid);

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_get_ssid: ssid=%s len=%d",
        ssid, ret);

    return (ret);
}

/* XXX: PRIVATE */
static int
wpa_driver_solaris_del_key(void *priv, int key_idx, const u8 *addr)
{
    dladm_status_t status;
    dladm_wlan_bssid_t bss;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "%s: id=%d", "wpa_driver_solaris_del_key",
        key_idx);

    if (addr != NULL)
        (void) memcpy(bss.wb_bytes, addr, DLADM_WLAN_BSSID_LEN);

    status = dladm_wlan_wpa_del_key(data->handle, data->linkid, key_idx, &bss);

    return (WPA_STATUS(status));
}

int
wpa_driver_solaris_set_key(const char *ifname, void *priv, enum wpa_alg alg,
    const u8 *addr, int key_idx, int set_tx,
    const u8 *seq, size_t seq_len,
    const u8 *key, size_t key_len)
{
    char *alg_name;
    dladm_wlan_cipher_t cipher;
    dladm_wlan_bssid_t bss;
    dladm_status_t status;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "%s", "wpa_driver_solaris_set_key");
    if (alg == WPA_ALG_NONE)
        return (wpa_driver_solaris_del_key(priv, key_idx, addr));

    switch (alg) {
    case WPA_ALG_WEP:
        alg_name = "WEP";
        cipher = DLADM_WLAN_CIPHER_WEP;
        break;
    case WPA_ALG_TKIP:
        alg_name = "TKIP";
        cipher = DLADM_WLAN_CIPHER_TKIP;
        break;
    case WPA_ALG_CCMP:
        alg_name = "CCMP";
        cipher = DLADM_WLAN_CIPHER_AES_CCM;
        break;
    default:
        wpa_printf(MSG_DEBUG, "wpa_driver_solaris_set_key:"
            " unknown/unsupported algorithm %d", alg);
        return (-1);
    }

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_set_key: alg=%s key_idx=%d"
        " set_tx=%d seq_len=%d seq=%d key_len=%d",
        alg_name, key_idx, set_tx,
        seq_len, *(uint64_t *)(uintptr_t)seq, key_len);

    if (seq_len > sizeof (uint64_t)) {
        wpa_printf(MSG_DEBUG, "wpa_driver_solaris_set_key:"
            " seq_len %d too big", seq_len);
        return (-1);
    }
    (void) memcpy(bss.wb_bytes, addr, DLADM_WLAN_BSSID_LEN);

    status = dladm_wlan_wpa_set_key(data->handle, data->linkid, cipher, &bss,
        set_tx, *(uint64_t *)(uintptr_t)seq, key_idx, (u8*) key, key_len);

    return (WPA_STATUS(status));
}

int
wpa_driver_solaris_disassociate(void *priv, const u8 *addr, int reason_code)
{
    dladm_status_t status;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_disassociate");

    status = dladm_wlan_wpa_set_mlme(data->handle, data->linkid,
        DLADM_WLAN_MLME_DISASSOC, reason_code, NULL);

    return (WPA_STATUS(status));
}

static boolean_t
wpa_driver_solaris_res_found(void *priv, dladm_wlan_attr_t *wlattr)
{
    size_t ssid_len;
    struct wpa_scan_res *result;
    u8 *pos;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "%s", "wpa_driver_solaris_res_found");

    data->results.num++;
    data->results.res = (struct wpa_scan_res **) os_realloc(data->results.res, data->results.num * sizeof(struct wpa_scan_res *));

    ssid_len = os_strlen(wlattr->wa_essid.we_bytes);
    result = data->results.res[data->results.num - 1] = (struct wpa_scan_res *) os_zalloc(sizeof(struct wpa_scan_res) + ssid_len + 2);

    os_memcpy(result->bssid, wlattr->wa_bssid.wb_bytes, ETH_ALEN);
    result->freq = 2407 + wlattr->wa_channel * 5;

    pos = (u8 *)(result + 1);
    *pos++ = WLAN_EID_SSID;
    *pos++ = ssid_len;
    os_memcpy(pos, wlattr->wa_essid.we_bytes, ssid_len);
    pos += ssid_len;

    result->ie_len = pos - (u8 *)(result + 1);

    if (wlattr->wa_bsstype == DLADM_WLAN_BSSTYPE_BSS)
        result->caps |= IEEE80211_CAP_ESS;
    else if (wlattr->wa_bsstype == DLADM_WLAN_BSSTYPE_IBSS)
        result->caps |= IEEE80211_CAP_IBSS;

    if (wlattr->wa_secmode != DLADM_WLAN_SECMODE_NONE)
        result->caps |= IEEE80211_CAP_PRIVACY;

    result->level = wlattr->wa_strength * 20;

    return B_TRUE;
}

int
wpa_driver_solaris_scan2(void *priv, struct wpa_driver_scan_params *params)
{
    uint_t i;
    dladm_status_t status;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "%s", "wpa_driver_solaris_scan2");

    /*
     * Free existing scan results
     * XXX DOUBLE CHECK THIS
     */
    for (i = 0; i < data->results.num; i++) {
        os_free(data->results.res[i]);
        data->results.res[i] = NULL;
    }
    os_free(data->results.res);
    data->results.res = NULL;
    data->results.num = 0;

    /*
     * We force the state to INIT before calling ieee80211_new_state
     * to get ieee80211_begin_scan called.  We really want to scan w/o
     * altering the current state but that's not possible right now.
     */
    (void) wpa_driver_solaris_disassociate(priv, NULL,
        DLADM_WLAN_REASON_DISASSOC_LEAVING);

    status = dladm_wlan_scan(data->handle, data->linkid, priv, wpa_driver_solaris_res_found);

    wpa_printf(MSG_DEBUG, "%s: return", "wpa_driver_solaris_scan");
    return (WPA_STATUS(status));
}

struct wpa_scan_results *
wpa_driver_solaris_get_scan_results2(void *priv)
{
    size_t extra_len;
    u8 *pos;
    uint_t ret, i, j;
    dladm_wlan_ess_t *ess;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "%s", "wpa_driver_solaris_get_scan_results2");

    ess = (dladm_wlan_ess_t *) os_zalloc(data->results.num * sizeof(dladm_wlan_ess_t));
    if (dladm_wlan_wpa_get_sr(data->handle, data->linkid, ess, data->results.num, &ret)
        != DLADM_STATUS_OK) {
        return NULL;
    }

    for (i = 0; i < data->results.num; i++)
        for (j = 0; j < data->results.num; j++) {
            if (os_memcmp(data->results.res[i]->bssid, ess[j].we_bssid.wb_bytes, DLADM_WLAN_BSSID_LEN) == 0) {
                extra_len = data->results.res[i]->ie_len + ess[j].we_wpa_ie_len;
                data->results.res[i] = (struct wpa_scan_res *) os_realloc(data->results.res[i], sizeof(struct wpa_scan_res) + extra_len);
                pos = (u8 *) (data->results.res[i] + 1) + data->results.res[i]->ie_len;

                os_memcpy(pos, ess[j].we_wpa_ie, ess[j].we_wpa_ie_len);
                data->results.res[i]->ie_len = extra_len;
            }
        }

    return &data->results;
}

int
wpa_driver_solaris_associate(void *priv, struct wpa_driver_associate_params *params)
{
    dladm_status_t status;
    dladm_wlan_bssid_t bss;
    wpa_driver_solaris_data *data = (wpa_driver_solaris_data*) priv;

    wpa_printf(MSG_DEBUG, "wpa_driver_solaris_associate : "
        MACSTR, MAC2STR(params->bssid));

    /*
     * NB: Don't need to set the freq or cipher-related state as
     * this is implied by the bssid which is used to locate
     * the scanned node state which holds it.
     */
    if (wpa_driver_solaris_set_wpa_ie(priv, params->wpa_ie, params->wpa_ie_len) < 0)
        return (-1);

    (void) memcpy(bss.wb_bytes, params->bssid, DLADM_WLAN_BSSID_LEN);
    status = dladm_wlan_wpa_set_mlme(data->handle, data->linkid, DLADM_WLAN_MLME_ASSOC,
        0, &bss);

    return (WPA_STATUS(status));
}

const struct wpa_driver_ops wpa_driver_solaris_ops = {
    .name              = "solaris",
    .desc              = "Solaris DLAPI wireless driver",
    .init              = wpa_driver_solaris_init,
    .deinit            = wpa_driver_solaris_deinit,
    .get_bssid         = wpa_driver_solaris_get_bssid,
    .get_ssid          = wpa_driver_solaris_get_ssid,
    .set_key           = wpa_driver_solaris_set_key,
    .scan2             = wpa_driver_solaris_scan2,
    .get_scan_results2 = wpa_driver_solaris_get_scan_results2,
    .associate         = wpa_driver_solaris_associate,
    .disassociate      = wpa_driver_solaris_disassociate,
};
