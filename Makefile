# bcmdhd
#
# Portions of this code are copyright (c) 2023 Cypress Semiconductor Corporation
#
# Copyright (C) 1999-2018, Broadcom Corporation
#
#      Unless you and Broadcom execute a separate written software license
# agreement governing use of this software, this software is licensed to you
# under the terms of the GNU General Public License version 2 (the "GPL"),
# available at http://www.broadcom.com/licenses/GPLv2.php, with the
# following added to such license:
#
#      As a special exception, the copyright holders of this software give you
# permission to link this software with independent modules, and to copy and
# distribute the resulting executable under terms of your choice, provided that
# you also meet, for each linked independent module, the terms and conditions of
# the license of that module.  An independent module is a module which is not
# derived from this software.  The special exception does not apply to any
# modifications of the software.
#
#      Notwithstanding the above, under no circumstances may you combine this
# software in any way with any other Broadcom software provided under a license
# other than the GPL, without Broadcom's express prior written consent.
#
#
# <<Broadcom-WL-IPTag/Open:>>
#

#####################
# Misc Build flags
#####################
ifeq ($(CONFIG_BCMDHD_PLATFORM_ROCKCHIP),y)
DHDCFLAGS += -DCONFIG_DHD_PLAT_ROCKCHIP
ifeq ($(CONFIG_BCMDHD_SDIO),y)
DHDCFLAGS += -DDHD_OF_SUPPORT
DHDCFLAGS += -DDHD_CUSTOM_PLAT_DATA
DHDOFILES += dhd_custom_rockchip.o
endif
endif

# Ignore unused wl_cfg80211_get_channel
# error: 'wl_cfg80211_get_channel' defined but not used
DHDCFLAGS += $(call cc-disable-warning, unused-function)

# Re-init driver when wpa_supplicant crashes.
# Due to supplicant crash/unclean de-initialization
# which didn't free the p2p discovery interface.
DHDCFLAGS += -DEXPLICIT_DISCIF_CLEANUP

# Some custom platform set CONFIG_ANDROID=y but unset
# CONFIG_ANDROID_VERSION. This hacking prevents this.
ifeq ($(CONFIG_ANDROID_VERSION),)
CONFIG_ANDROID_VERSION := 0
endif

# Reset PCIe card using function level reset on probing.
# The driver may exit irregularly before and the probe
# may fails on si_attach().
ifneq ($(CONFIG_BCMDHD_PCIE),)
DHDCFLAGS += -DRESET_PCIE_ON_PROBE
endif

# Reset SDIO card using mmc_hw_reset on probing.
# The driver may exit irregularly before and the probe
# may fails on bootloader ready timeout.
ifeq ($(CONFIG_BCMDHD_SDIO),y)
DHDCFLAGS += -DRESET_SDIO_ON_PROBE
endif

DHDCFLAGS += -DWL_VIF_SUPPORT

#####################
# SDIO Basic feature
#####################

DHDCFLAGS += -Wall -Wstrict-prototypes -Dlinux -DLINUX -DBCMDRIVER            \
	-DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32 -DBCMFILEIMAGE            \
	-DDHDTHREAD -DSHOW_EVENTS -DBCMDBG -DWLP2P                            \
	-DWIFI_ACT_FRAME -DARP_OFFLOAD_SUPPORT                                \
	-DKEEP_ALIVE -DCSCAN -DPKT_FILTER_SUPPORT                             \
	-DEMBEDDED_PLATFORM -DPNO_SUPPORT -DSHOW_LOGTRACE                     \
	-DGET_CUSTOM_MAC_ENABLE      \
	-DSEC_ENHANCEMENT -DDHD_FW_COREDUMP -DCHIPS_CUSTOMER_HW6	\
	-DDHD_RND_DEBUG -DDHD_DUMP_FILE_WRITE_FROM_KERNEL		\
	-DDHD_DONOT_FORWARD_BCMEVENT_AS_NETWORK_PKT

GCCVERSIONGTEQ9 := $(shell expr `$(CROSS_COMPILE)gcc -dumpversion | cut -f1 -d.` \>= 9)
ifeq "$(GCCVERSIONGTEQ9)" "1"
    DHDCFLAGS += -Wno-error=date-time
endif
GCCVERSIONGTEQ7 := $(shell expr `$(CROSS_COMPILE)gcc -dumpversion | cut -f1 -d.` \>= 7)
ifeq "$(GCCVERSIONGTEQ7)" "1"
    DHDCFLAGS += -Wimplicit-fallthrough=3
endif
DHDCFLAGS += $(call cc-disable-warning, date-time)
DHDCFLAGS += $(call cc-disable-warning, stringop-overflow)

#################
# Common feature
#################
DHDCFLAGS += -DAUTOMOTIVE_FEATURE
DHDCFLAGS += -DWL_VIRTUAL_APSTA
# Dongle init fail
DHDCFLAGS += -DDEBUG_DNGL_INIT_FAIL
DHDCFLAGS += -DPOWERUP_MAX_RETRY=0
DHDCFLAGS += -DWL_SUPPORT_AUTO_CHANNEL

# Wapi
DHDCFLAGS += -DBCMWAPI_WPI -DBCMWAPI_WAI

# Allow wl event forwarding as network packet
DHDCFLAGS += -DWL_EVENT_ENAB

DHDCFLAGS += -DWL_CFG80211
# Print out kernel panic point of file and line info when assertion happened
DHDCFLAGS += -DBCMASSERT_LOG

# Enable Log Dump
DHDCFLAGS += -DDHD_LOG_DUMP
DHDCFLAGS += -DOEM_ANDROID

# Enable Register access via dhd IOVAR
DHDCFLAGS += -DDHD_PCIE_REG_ACCESS -DDHD_BUS_MEM_ACCESS

# CUSTOMER4 flags
DHDCFLAGS += -DDHD_PKTID_AUDIT_ENABLED
DHDCFLAGS += -DSUPPORT_HIDDEN_AP
DHDCFLAGS += -DPASS_ALL_MCAST_PKTS -DESCAN_BUF_OVERFLOW_MGMT -DPKTPRIO_OVERRIDE
DHDCFLAGS += -DUSE_INITIAL_SHORT_DWELL_TIME
DHDCFLAGS += -DSOFTAP_UAPSD_OFF
DHDCFLAGS += -DSUPPORT_LTECX -DSUPPORT_2G_VHT
DHDCFLAGS += -DSUPPORT_WL_TXPOWER -DBLOCK_IPV6_PACKET -DSUPPORT_DEEP_SLEEP
DHDCFLAGS += -DSUPPORT_AMPDU_MPDU_CMD -DSOFTAP_SEND_HANGEVT -DNUM_SCB_MAX_PROBE=3
DHDCFLAGS += -DCUSTOM_TCPACK_DELAY_TIME=10
DHDCFLAGS += -DDEBUGFS_CFG80211
DHDCFLAGS += -DSUPPORT_SOFTAP_WPAWPA2_MIXED
DHDCFLAGS += -DSUPPORT_2G_VHT -DSUPPORT_5G_1024QAM_VHT
DHDCFLAGS += -DEWP_ECNTRS_LOGGING
DHDCFLAGS += -DEWP_ETD_PRSRV_LOGS
DHDCFLAGS += -DCFI_CHECK

# Runtime PM feature
# DHDCFLAGS += -DDHD_PCIE_RUNTIMEPM -DMAX_IDLE_COUNT=11 -DCUSTOM_DHD_RUNTIME_MS=100

# DMA64 suppports on 64bit Architecture
ifeq ($(CONFIG_ARM64),y)
	DHDCFLAGS := $(filter-out -DBCMDMA32,$(DHDCFLAGS))
	DHDCFLAGS += -DBCMDMA64OSL
endif

# DMA64 suppports on x64bit Architecture
#ifeq ($(CONFIG_64BIT),y)
#	DHDCFLAGS := $(filter-out -DBCMDMA32,$(DHDCFLAGS))
#	DHDCFLAGS += -DBCMDMA64OSL
#endif // endif

## OOB
ifneq ($(CONFIG_BCMDHD_PCIE),)
ifeq ($(CONFIG_BCMDHD_OOB_HOST_WAKE),y)
	DHDCFLAGS += -DBCMPCIE_OOB_HOST_WAKE
else
	DHDCFLAGS += -DPCIE_ISR_THREAD
endif
endif

ifeq ($(CONFIG_BCMDHD_SDIO),y)
ifeq ($(CONFIG_BCMDHD_OOB_HOST_WAKE),y)
	DHDCFLAGS += -DOOB_INTR_ONLY
else
	DHDCFLAGS += -DSDIO_ISR_THREAD
endif
endif

# keepalive
DHDCFLAGS += -DCUSTOM_KEEP_ALIVE_SETTING=28000

#OWE enable in dhd
DHDCFLAGS += -DWL_OWE

DHDCFLAGS += -DVSDB

# For p2p connection issue
DHDCFLAGS += -DWL_SCB_TIMEOUT=10

# TDLS enable
DHDCFLAGS += -DWLTDLS -DWLTDLS_AUTO_ENABLE
# For TDLS tear down inactive time 40 sec
DHDCFLAGS += -DCUSTOM_TDLS_IDLE_MODE_SETTING=10000
# for TDLS RSSI HIGH for establishing TDLS link
DHDCFLAGS += -DCUSTOM_TDLS_RSSI_THRESHOLD_HIGH=-80
# for TDLS RSSI HIGH for tearing down TDLS link
DHDCFLAGS += -DCUSTOM_TDLS_RSSI_THRESHOLD_LOW=-85

# Roaming
DHDCFLAGS += -DROAM_AP_ENV_DETECTION
DHDCFLAGS += -DROAM_ENABLE -DROAM_CHANNEL_CACHE -DROAM_API
DHDCFLAGS += -DENABLE_FW_ROAM_SUSPEND
# Roaming trigger
DHDCFLAGS += -DCUSTOM_ROAM_TRIGGER_SETTING=-75
DHDCFLAGS += -DCUSTOM_ROAM_DELTA_SETTING=10
# Set PM 2 always regardless suspend/resume
DHDCFLAGS += -DSUPPORT_PM2_ONLY

# FT roam
DHDCFLAGS += -DWLFBT -DGTK_OFFLOAD_SUPPORT
DHDCFLAGS += -DBCMCCX
DHDCFLAGS += -DWBTEXT
DHDCFLAGS += -DDHD_LOSSLESS_ROAMING

# Hog flags
ifeq ($(CONFIG_ENABLE_HOGSQS), y)
DHDCFLAGS += -DENABLE_HOGSQS
DHDCFLAGS += -DM_HOGSQS_CFG=0x1910
endif

# For special PNO Event keep wake lock for 10sec
DHDCFLAGS += -DCUSTOM_PNO_EVENT_LOCK_xTIME=10
DHDCFLAGS += -DMIRACAST_AMPDU_SIZE=8
#Vendor Extension
#DHDCFLAGS += -DWL_VENDOR_EXT_SUPPORT
#Gscan
DHDCFLAGS += -DGSCAN_SUPPORT
#PNO Scan Result Version
DHDCFLAGS += -DPFN_SCANRESULT_2
#RSSI Monitor
DHDCFLAGS += -DRSSI_MONITOR_SUPPORT
#APF
DHDCFLAGS += -DAPF
#NDOffload
DHDCFLAGS += -DNDO_CONFIG_SUPPORT
DHDCFLAGS += -DIPV6_NDO_SUPPORT

#Link Statistics
DHDCFLAGS += -DLINKSTAT_SUPPORT

#Debugaility
DHDCFLAGS += -DDBG_PKT_MON -DDBG_PKT_MON_INIT_DEFAULT
DHDCFLAGS += -DWL_SCHED_SCAN
DHDCFLAGS += -DDNGL_EVENT_SUPPORT

#RSSI Monitor
DHDCFLAGS += -DRSSI_MONITOR_SUPPORT

# Early suspend
DHDCFLAGS += -DDHD_USE_EARLYSUSPEND

# For Scan result patch
DHDCFLAGS += -DESCAN_RESULT_PATCH

# NAN
#DHDCFLAGS += -DWL_NAN -DWL_NAN_DISC_CACHE

# For Static Buffer
ifeq ($(CONFIG_DHD_USE_STATIC_BUF),y)
  DHDCFLAGS += -DENHANCED_STATIC_BUF
  DHDCFLAGS += -DSTATIC_WL_PRIV_STRUCT
endif
ifneq ($(CONFIG_DHD_USE_SCHED_SCAN),)
DHDCFLAGS += -DWL_SCHED_SCAN
endif

# Prevent rx thread monopolize
DHDCFLAGS += -DWAIT_DEQUEUE

# idle count
DHDCFLAGS += -DDHD_USE_IDLECOUNT

# SKB TAILPAD to avoid out of boundary memory access
DHDCFLAGS += -DDHDENABLE_TAILPAD

# Wi-Fi Direct
DHDCFLAGS += -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
DHDCFLAGS += -DWL_CFG80211_STA_EVENT
DHDCFLAGS += -DWL_IFACE_COMB_NUM_CHANNELS
DHDCFLAGS += -DWL_SUPPORT_MULTIP2P
#SCAN time
DHDCFLAGS += -DCUSTOM_SET_SHORT_DWELL_TIME
DHDCFLAGS += -DCUSTOM_FORCE_NODFS_FLAG
ifeq ($(CONFIG_ANDROID),y)
  DHDCFLAGS += -DKEEP_WIFION_OPTION
  DHDCFLAGS += -Wno-date-time

#Android features
ifeq ($(shell expr $(CONFIG_ANDROID_VERSION) \>= 12), 1)
# For android toolchain.
 DHDCFLAGS += -Wno-unused-const-variable
 DHDCFLAGS += -Wno-unneeded-internal-declaration
ifeq ($(shell expr $(CONFIG_ANDROID_VERSION) \>= 13), 1)
 DHDCFLAGS += -Wno-unused-but-set-variable
 DHDCFLAGS += -DDHD_ANDROID_KERNEL5_15_SUPPORT
endif

 DHDCFLAGS += -DCONFIG_ANDROID_VERSION=$(CONFIG_ANDROID_VERSION)
 DHDCFLAGS += -DP2P_RAND
 DHDCFLAGS += -DSOFTAP_RAND
 DHDCFLAGS += -DSTA_RAND
#To support Android12 CDD [C-1-7] [C-1-8] [C-1-9] [C-1-10]
 DHDCFLAGS += -DSUPPORT_RANDOM_MAC_SCAN

#To support recovery
 DHDCFLAGS += -DWL_CFGVENDOR_SEND_HANG_EVENT

 DHDCFLAGS += -DWL_SELF_MANAGED_REGDOM
 DHDCFLAGS += -DDHD_DIRECT_SET_MAC
 DHDCFLAGS += -DWL_SUPPORT_BSS_BOOTTIME

# To support Android Common kernel
ifneq ($(CONFIG_HAVE_IMX8_SOC),y)
DHDCFLAGS += -DDHD_SUPPORT_REQFW_FOR_FIRMWARE_DOWNLOADING -DDHD_DENY_DIRECT_FS_ACCESS
endif

# To support ACS on hostapd
# DHDCFLAGS += -DWL_SUPPORT_ACS_OFFLOAD
endif
endif

# SoftAP
DHDCFLAGS += -DSET_RANDOM_MAC_SOFTAP
DHDCFLAGS += -DWL_CFG80211_ACL
ifeq ($(CONFIG_WL_AP_IF),y)
  DHDCFLAGS += -DWL_STATIC_IF
  DHDCFLAGS += -DDHD_NUM_STATIC_IFACES=2
endif

# QT support
ifeq ($(CONFIG_QT), y)
  DHDCFLAGS += -DBCMQT_HW -DBCMSLTGT -DBCMQT
endif

# Disable FRAMEBURST on VSDB
DHDCFLAGS += -DDISABLE_FRAMEBURST_VSDB

# WPS
DHDCFLAGS += -DWL_WPS_SYNC -DBCMCRYPTO_COMPONENT

#WPA3
ifneq ($(CONFIG_BCMDHD_WPA3),)
 DHDCFLAGS += -DWL_SAE
endif

ifneq ($(CONFIG_BCMDHD_PCIE),)
DHDCFLAGS += -DDHD_4WAYM4_FAIL_DISCONNECT
endif

#802.11ax and 6Ghz Support
ifeq ($(CONFIG_BCMDHD_WIFI6_6E),y)
 DHDCFLAGS += -DWL11AX
 DHDCFLAGS += -DWL_6E
endif

#XR Support
ifeq ($(CONFIG_BCMDHD_XR_SUPPORT),y)
 DHDCFLAGS += -DWL_DHD_XR -DWL_DHD_XR_LOG
ifneq ($(CONFIG_BCMDHD),)
 DHDCFLAGS += -DWL_DHD_XR_MASTER
endif
ifneq ($(CONFIG_BCMDHDX),)
 DRIVER_TYPE ?= $(CONFIG_BCMDHDX)
 DHDCFLAGS += -DBCMDHDX -DWL_DHD_XR_CLIENT
endif
 # Bandsteer support
 DHDCFLAGS += -DDHD_BANDSTEER
 DHDOFILES += wl_cfg80211_xr.o dhd_linux_xr.o
endif

#IFX cfg80211 support
ifeq ($(CONFIG_BCMDHD_IFX_CFG80211),y)
 #For 5.4.21 kernel
 DHDCFLAGS += -DIFX_CFG80211_5_4_21
endif

# Uncomment the below line for AP to receive disconnect management frame.
# DHDCFLAGS += -DWL_CFG80211_AP_RX_MGMT_DISCONNECT

# Bandsteer support
# DHDCFLAGS += -DDHD_BANDSTEER

##########################
# driver type
# m: module type driver
# y: built-in type driver
##########################
ifneq ($(CONFIG_BCMDHD),)
DRIVER_TYPE ?= $(CONFIG_BCMDHD)
endif

#############################
# Bring up WARs for CYW89570.
# # To be removed later
# #############################
ifneq ($(CONFIG_WIRELESS_EXT),)
  DHDOFILES += wl_iw.o bcm_app_utils.o
  DHDCFLAGS += -DWL_WIRELESS_EXT -DWLLXIW -DUSE_IW
endif

ifeq ($(CONFIG_TRXHDR_V3),y)
   DHDCFLAGS += -DBCMTRXV3
else
   DHDCFLAGS += -DBCMTRXV4
endif

#########################
# Chip dependent feature
#########################

  DHDCFLAGS += -DUSE_WL_TXBF
  DHDCFLAGS += -DCUSTOM_DPC_CPUCORE=0

# New Features
  DHDCFLAGS += -DWL11U
  DHDCFLAGS += -DMFP
# Disabling LPC for 89570 for now.
# DHDCFLAGS += -DDHD_ENABLE_LPC
  DHDCFLAGS += -DCUSTOM_COUNTRY_CODE
  DHDCFLAGS += -DNDO_CONFIG_SUPPORT
  DHDCFLAGS += -DIPV6_NDO_SUPPORT
  DHDCFLAGS += -DIGUANA_LEGACY_CHIPS

ifeq ($(CONFIG_BCMDHD_SDMMC),y)
  DHDCFLAGS += -DBCMLXSDMMC -DCUSTOM_TXGLOM=1
ifneq ($(CONFIG_HAVE_IMX8_SOC),)
  DHDCFLAGS += \
  	-DCONFIG_DTS \
	-DOEM_EMBEDDED_LINUX \
	-DPLATFORM_IMX
ifeq ($(shell expr $(CONFIG_ANDROID_VERSION) \>= 13), 1)
  DHDCFLAGS += -Wno-unused-function
endif
endif
endif

ifeq ($(CONFIG_BCMDHD_SDIOH_STD),y)
  DHDCFLAGS += -DBCMSDIOH_STD
endif

ifeq ($(CONFIG_BCMDHD_SDIO),y)
  DHDCFLAGS += -DBDC -DHW_OOB -DDHD_BCMEVENTS -DMMC_SDIO_ABORT
  DHDCFLAGS += -DBCMSDIO -DUSE_SDIOFIFO_IOVAR
  DHDCFLAGS += -DPROP_TXSTATUS -DLIMIT_BORROW
  DHDCFLAGS += -DPROP_TXSTATUS_VSDB
  DHDCFLAGS += -DUSE_WL_FRAMEBURST
# tput enhancement
  DHDCFLAGS += -DCUSTOM_GLOM_SETTING=8 -DCUSTOM_RXCHAIN=1
  DHDCFLAGS += -DUSE_DYNAMIC_F2_BLKSIZE -DDYNAMIC_F2_BLKSIZE_FOR_NONLEGACY=128
  DHDCFLAGS += -DBCMSDIOH_TXGLOM -DAMPDU_HOSTREORDER
  DHDCFLAGS += -DDHDTCPACK_SUPPRESS
  DHDCFLAGS += -DRXFRAME_THREAD
  DHDCFLAGS += -DREPEAT_READFRAME
  DHDCFLAGS += -DCUSTOM_MAX_TXGLOM_SIZE=40
  DHDCFLAGS += -DMAX_HDR_READ=128
  DHDCFLAGS += -DDHD_FIRSTREAD=64
  DHDCFLAGS += -DDHD_WAKE_STATUS -DDHD_WAKE_RX_STATUS
ifneq ($(CONFIG_BCM4373),)
  DHDCFLAGS += -DCUSTOM_AMPDU_BA_WSIZE=32
else
  DHDCFLAGS += -DCUSTOM_AMPDU_BA_WSIZE=64

endif

# bcn_timeout
  DHDCFLAGS += -DCUSTOM_BCN_TIMEOUT_SETTING=5

  DHDCFLAGS += -DWLFC_STATE_PREALLOC
  DHDCFLAGS += -DREVERSE_AIFSN

# btsharedsdio
ifneq  ($(CONFIG_BT_OVER_SDIO),)
  DHDCFLAGS += -DBT_OVER_SDIO
endif
endif

# Expand TCP tx queue to 10 times of default size
  DHDCFLAGS += -DTSQ_MULTIPLIER=10

ifneq ($(CONFIG_BCMDHD_PCIE),)
  DHDCFLAGS += -DPCIE_FULL_DONGLE -DBCMPCIE -DCUSTOM_DPC_PRIO_SETTING=-1
# tput enhancement
  DHDCFLAGS += -DCUSTOM_AMPDU_BA_WSIZE=64
  DHDCFLAGS += -DPROP_TXSTATUS_VSDB
# Disable watchdog thread
  DHDCFLAGS += -DCUSTOM_DHD_WATCHDOG_MS=0
# HEAP ASLR
  DHDCFLAGS += -DBCM_ASLR_HEAP
  DHDCFLAGS += -DMAX_CNTL_TX_TIMEOUT=1
ifneq ($(CONFIG_ARCH_MSM),)
  DHDCFLAGS += -DMSM_PCIE_LINKDOWN_RECOVERY
endif
ifeq ($(CONFIG_DHD_USE_STATIC_BUF),y)
  DHDCFLAGS += -DDHD_USE_STATIC_IOCTLBUF
endif
ifeq ($(CONFIG_BCMDHD_COHERENT_MEM_RING),y)
DHDCFLAGS += -DDHD_USE_COHERENT_MEM_FOR_RING
endif
# Enable health check event handling
  DHDCFLAGS += -DDNGL_EVENT_SUPPORT
  DHDCFLAGS += -DHCHK_COMMON_SW_EVENT

# Enable Load Balancing support by default.
# DHD_LB_RXP - Perform RX Packet processing in parallel
# DHD_LB_STATS - To display the Load Blancing statistics
DHDCFLAGS += -DDHD_LB -DDHD_LB_RXP -DDHD_LB_STATS
DHDCFLAGS += -DDHD_LB_PRIMARY_CPUS=0xF0 -DDHD_LB_SECONDARY_CPUS=0x0E

# Runtime PM feature
# DHDCFLAGS += -DDHD_PCIE_RUNTIMEPM -DMAX_IDLE_COUNT=11 -DCUSTOM_DHD_RUNTIME_MS=100

# debug info
  DHDCFLAGS += -DDHD_WAKE_STATUS -DDHD_WAKE_RX_STATUS

# Enable SSSR Dump
  DHDCFLAGS += -DDHD_SSSR_DUMP
endif

# Print 802.1X packets
  DHDCFLAGS += -DDHD_8021X_DUMP
# prioritize 802.1x packet
  DHDCFLAGS += -DEAPOL_PKT_PRIO

# Enable MSI interrupt Support
  DHDCFLAGS += -DDHD_MSI_SUPPORT

# Enabling temporarily due to build failure
 DHDCFLAGS += -DDHD_PKTTS -DTX_STATUS_LATENCY_STATS

ifneq ($(filter y, $(CONFIG_BCM4354) $(CONFIG_BCM4356)),)
  DHDCFLAGS += -DUSE_WL_TXBF
  DHDCFLAGS += -DUSE_WL_FRAMEBURST
  DHDCFLAGS += -DCUSTOM_DPC_CPUCORE=0
  DHDCFLAGS += -DPROP_TXSTATUS_VSDB
  DHDCFLAGS += -DCUSTOM_PSPRETEND_THR=30
  DHDCFLAGS += -DMAX_AP_CLIENT_CNT=10
  DHDCFLAGS += -DMAX_GO_CLIENT_CNT=5
# New Features
  DHDCFLAGS += -DWL11U
  DHDCFLAGS += -DMFP
  DHDCFLAGS += -DDHD_ENABLE_LPC
  DHDCFLAGS += -DCUSTOM_COUNTRY_CODE
  DHDCFLAGS += -DSAR_SUPPORT
# debug info
  DHDCFLAGS += -DDHD_WAKE_STATUS
ifeq ($(CONFIG_BCMDHD_SDIO),y)
#  DHDCFLAGS += -DBDC -DOOB_INTR_ONLY -DHW_OOB -DDHD_BCMEVENTS -DMMC_SDIO_ABORT
  DHDCFLAGS += -DBDC -DHW_OOB -DDHD_BCMEVENTS -DMMC_SDIO_ABORT
  DHDCFLAGS += -DBCMSDIO -DBCMLXSDMMC -DUSE_SDIOFIFO_IOVAR
  DHDCFLAGS += -DPROP_TXSTATUS
  DHDCFLAGS += -DCUSTOM_AMPDU_MPDU=16
  DHDCFLAGS += -DCUSTOM_AMPDU_BA_WSIZE=64
# tput enhancement
  DHDCFLAGS += -DCUSTOM_GLOM_SETTING=8 -DCUSTOM_RXCHAIN=1
  DHDCFLAGS += -DUSE_DYNAMIC_F2_BLKSIZE -DDYNAMIC_F2_BLKSIZE_FOR_NONLEGACY=128
  DHDCFLAGS += -DBCMSDIOH_TXGLOM -DCUSTOM_TXGLOM=1 -DBCMSDIOH_TXGLOM_HIGHSPEED
  DHDCFLAGS += -DDHDTCPACK_SUPPRESS
  DHDCFLAGS += -DRXFRAME_THREAD
  DHDCFLAGS += -DREPEAT_READFRAME
  DHDCFLAGS += -DCUSTOM_MAX_TXGLOM_SIZE=40
  DHDCFLAGS += -DMAX_HDR_READ=128
  DHDCFLAGS += -DDHD_FIRSTREAD=128
# bcn_timeout
  DHDCFLAGS += -DCUSTOM_BCN_TIMEOUT=5
  DHDCFLAGS += -DWLFC_STATE_PREALLOC
endif

ifneq ($(CONFIG_BCMDHD_PCIE),)
  DHDCFLAGS += -DPCIE_FULL_DONGLE -DBCMPCIE -DCUSTOM_DPC_PRIO_SETTING=-1
# tput enhancement
  DHDCFLAGS += -DCUSTOM_AMPDU_BA_WSIZE=64
  DHDCFLAGS += -DPROP_TXSTATUS_VSDB
# Disable watchdog thread
  DHDCFLAGS += -DCUSTOM_DHD_WATCHDOG_MS=0
  DHDCFLAGS += -DMAX_CNTL_TX_TIMEOUT=1
  DHDCFLAGS += -DSUPPORT_LINKDOWN_RECOVERY
# Enable health check event handling
  DHDCFLAGS += -DDNGL_EVENT_SUPPORT
  DHDCFLAGS += -DHCHK_COMMON_SW_EVENT
endif
ifeq ($(CONFIG_DHD_USE_STATIC_BUF),y)
  DHDCFLAGS += -DDHD_USE_STATIC_IOCTLBUF
endif
# Print 802.1X packets
  DHDCFLAGS += -DDHD_8021X_DUMP
# Print DHCP packets
  DHDCFLAGS += -DDHD_DHCP_DUMP
endif

ifneq ($(CONFIG_BCM4339),)
  DHDCFLAGS += -DBCM4339_CHIP -DHW_OOB

  # tput enhancement
  DHDCFLAGS += -DCUSTOM_GLOM_SETTING=8 -DCUSTOM_RXCHAIN=1
  DHDCFLAGS += -DUSE_DYNAMIC_F2_BLKSIZE -DDYNAMIC_F2_BLKSIZE_FOR_NONLEGACY=128
  DHDCFLAGS += -DBCMSDIOH_TXGLOM -DCUSTOM_TXGLOM=1 -DBCMSDIOH_TXGLOM_HIGHSPEED
  DHDCFLAGS += -DDHDTCPACK_SUPPRESS
  DHDCFLAGS += -DUSE_WL_TXBF
  DHDCFLAGS += -DUSE_WL_FRAMEBURST
  DHDCFLAGS += -DRXFRAME_THREAD
  DHDCFLAGS += -DCUSTOM_AMPDU_BA_WSIZE=64
  DHDCFLAGS += -DCUSTOM_DPC_CPUCORE=0
  DHDCFLAGS += -DPROP_TXSTATUS_VSDB
  DHDCFLAGS += -DCUSTOM_MAX_TXGLOM_SIZE=32

  # New Features
  DHDCFLAGS += -DWL11U
  DHDCFLAGS += -DDHD_ENABLE_LPC
  DHDCFLAGS += -DCUSTOM_PSPRETEND_THR=30
endif

#EXTRA_LDFLAGS += --strip-debug

ifeq ($(DRIVER_TYPE),y)
  DHDCFLAGS += -DENABLE_INSMOD_NO_FW_LOAD
  DHDCFLAGS += -DUSE_LATE_INITCALL_SYNC
  # Use kernel strlcpy() implementation instead of one, defined in bcmstdlib_s.c
  DHDCFLAGS += -DBCM_USE_PLATFORM_STRLCPY
endif

DHDOFILES += dhd_pno.o dhd_common.o dhd_ip.o dhd_custom_gpio.o \
    dhd_linux.o dhd_linux_sched.o dhd_cfg80211.o dhd_linux_wq.o aiutils.o \
    bcmevent.o bcmutils.o bcmwifi_channels.o hndpmu.o linux_osl.o linux_pkt.o \
    sbutils.o siutils.o wl_android.o wl_roam.o wl_cfg80211.o wl_cfgscan.o wl_cfgp2p.o \
    wl_cfg_btcoex.o wldev_common.o dhd_linux_platdev.o \
    dhd_pno.o dhd_linux_pktdump.o wl_cfg_btcoex.o hnd_pktq.o \
    hnd_pktpool.o wl_cfgvendor.o bcmxtlv.o bcm_app_utils.o dhd_debug.o \
    dhd_debug_linux.o dhd_mschdbg.o bcmbloom.o dhd_dbg_ring.o bcmstdlib_s.o \
    dhd_linux_exportfs.o wl_twt.o

ifneq ($(CONFIG_DHD_MONITOR_INTERFACE),)
    DHDCFLAGS += -DDHD_MONITOR_INTERFACE
    DHDOFILES += wl_linux_mon.o
else ifeq ($(CONFIG_BCMDHD_P2P_IF),y)
	DHDCFLAGS += -DWL_ENABLE_P2P_IF
endif

ifneq ($(CONFIG_DHD_OF_SUPPORT),)
    DHDCFLAGS += -DDHD_OF_SUPPORT
ifeq ($(CONFIG_ARCH_MSM),y)
    DHDOFILES += dhd_custom_msm.o
endif

ifneq ($(CONFIG_BROADCOM_WIFI_RESERVED_MEM),)
  DHDOFILES += dhd_custom_memprealloc.o
endif
endif

ifeq ($(CONFIG_BCMDHD_SDMMC),y)
  DHDOFILES += bcmsdh_sdmmc.o bcmsdh_sdmmc_linux.o
endif

ifeq ($(CONFIG_BCMDHD_SDIO),y)
  DHDOFILES += bcmsdh.o bcmsdh_linux.o
  DHDOFILES += dhd_cdc.o dhd_wlfc.o dhd_sdio.o
endif

ifeq ($(CONFIG_BCMDHD_SDIOH_STD),y)
  DHDOFILES += bcmsdstd.o bcmsdstd_linux.o
endif

ifneq ($(CONFIG_BCMDHD_PCIE),)
  DHDOFILES += dhd_pcie.o dhd_pcie_linux.o dhd_msgbuf.o dhd_flowring.o
  DHDOFILES += pcie_core.o
endif

ifneq ($(filter -DDHD_LB, $(DHDCFLAGS)),)
DHDOFILES += dhd_linux_lb.o
endif
ifneq ($(filter -DDHD_BANDSTEER, $(DHDCFLAGS)),)
    DHDOFILES += dhd_bandsteer.o
endif

ifneq ($(CONFIG_QT),y)
  DHDCFLAGS += -DRTT_SUPPORT -DRTT_DEBUG
  DHDOFILES += dhd_rtt.o
endif
EXTRA_CFLAGS += $(DHDCFLAGS) -DDHD_DEBUG
EXTRA_CFLAGS += -DSRCBASE=\"$(src)\"
EXTRA_CFLAGS += -I$(src)/include/ -I$(src)/
KBUILD_CFLAGS += -I$(KDIR)/include -I$(CURDIR)

ifneq ($(CONFIG_BCMDHD),)
bcmdhd-objs := $(DHDOFILES)
obj-$(DRIVER_TYPE)   += bcmdhd.o
endif

ifneq ($(CONFIG_BCMDHDX),)
bcmdhdx-objs := $(DHDOFILES)
obj-$(DRIVER_TYPE) += bcmdhd.o bcmdhdx.o
endif

all:
	@echo "$(MAKE) --no-print-directory -C $(KDIR) M=$(CURDIR) modules"
	@$(MAKE) --no-print-directory -C $(KDIR) M=$(CURDIR) modules

clean:
	rm -rf *.o *.ko *.mod.c *~ .*.cmd *.o.cmd .*.o.cmd .*.o.d *.mod \
	Module.symvers modules.order .tmp_versions modules.builtin

install:
	@$(MAKE) --no-print-directory -C $(KDIR) \
		SUBDIRS=$(CURDIR) modules_install
