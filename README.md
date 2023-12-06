# Dongle Host Driver for IFX Combo Chips (Modified to some extent)
## Tested Chips
SDIO:  
> CYW43438  
> CYW43455  
> CYW5557X  

PCIE:  
> CYW5557X  

For full support device, please see MODULE_DEVICE_TABLE in bcmsdh_sdmmc_linux.c/dhd_pcie_linux.c.  
## Tested Build Flags
> CONFIG_BCMDHD  
> CONFIG_BCMDHD_SDIO  
> CONFIG_BCMDHD_SDMMC  
> CONFIG_BCMDHD_PCIE  
> CONFIG_BCMDHD_WPA3  
> CONFIG_BCMDHD_WIFI6_6E  
> CONFIG_BCMDHD_IFX_CFG80211  
> CONFIG_BCMDHD_P2P_IF  
> CONFIG_BCMDHD_PLATFORM_GENERIC  
> CONFIG_BCMDHD_PLATFORM_ROCKCHIP  
> CONFIG_BCMDHD_OOB_HOST_WAKE  
> CONFIG_HAVE_IMX8_SOC  

For detailed information, please see Makefile.  
## Build
Setup build environment (example):  
```
export KDIR=/path/to/kernel/src
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
```
Build for SDIO:  
```
make -j$(grep -c processor /proc/cpuinfo) CONFIG_BCMDHD=m CONFIG_BCMDHD_IFX_CFG80211=y CONFIG_BCMDHD_SDIO=y CONFIG_BCMDHD_SDMMC=y CONFIG_BCMDHD_P2P_IF=y CONFIG_BCMDHD_WPA3=y CONFIG_BCMDHD_WIFI6_6E=y
```
Build for PCIE:
```
make -j$(grep -c processor /proc/cpuinfo) CONFIG_BCMDHD=m CONFIG_BCMDHD_IFX_CFG80211=y CONFIG_BCMDHD_PCIE=y CONFIG_BCMDHD_P2P_IF=y CONFIG_BCMDHD_WPA3=y CONFIG_BCMDHD_WIFI6_6E=y
```
