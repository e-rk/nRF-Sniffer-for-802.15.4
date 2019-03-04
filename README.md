# nRF 802.15.4 sniffer

This repository contains firmware and Wireshark extcap script that can be used with nRF52840 chip as an 802.15.4 sniffer.

__Note:__ this project is experimental.

The software provided has been tested with the nRF52840-DK board and the following operating systems:
* Ubuntu 18.04 (Wireshark 2.4.5 from the official package, Wireshark 2.6.4)
* Windows 10 (Wireshark 2.6.3)
* macOS Mojave (Wireshark 2.6.4)

## Dependencies
* Wireshark (Ubuntu package `wireshark`)
* pySerial (Ubuntu package `python-serial` or `python3-serial`)

## Quick start guide

To start using the sniffer, you must flash the firmware, install the script, and configure the sniffer in Wireshark.

### Flash firmware

#### nRF52840-DK (PCA10056)
1. Connect the nRF52840-DK to the PC with an USB cable by connecting it to the J2 USB port.
2. Flash the firmware with the following command:
```
nrfjprog -f nrf52 --program nrf802154_sniffer/nrf802154_sniffer.hex --chiperase -r
```
3. J2 USB port can now be optionally disconnected.
4. Connect the nRF52840-DK to J3 nRF USB port.

__Note:__ Sniffer firmware can no longer transport captured packets over J2 USB port. Capture can be carried out using only the J3 nRF USB port.

#### nRF52840-Dongle (PCA10059)

1. Download and install [nRF Connect for Desktop](https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Connect-for-desktop).
2. Click `Add/remove apps` and install `Programmer` application.
3. Plug the dongle to USB port and click reset button to enter DFU mode. Red diode should start blinking.
4. Select `Nordic Semiconductor DFU Bootloader` device from the list.
5. Click `Add HEX file` and select `nrf802154_sniffer_dongle.hex` from `nrf802154_sniffer` directory.
6. Verify that the selected application begins at the `0x00001000` address to avoid overwriting the MBR section.
7. Click `Write` to flash the device.
8. Unplug the dongle from the USB port and plug it again. Do not click the reset button.

### Install extcap script

To find the correct installation path of the extcap utility on any system please see:
```
"Help" -> "About Wireshark" -> "Folders" -> "Extcap path"
```
Copy the provided `nrf802154_sniffer.py` script to the extcap directory.

__Note to Windows users:__ `nrf802154_sniffer.bat` has to be copied to the same directory as well.
Ensure that Python directory is included in your `PATH` system environment variable.

### Start sniffing
1. Run Wireshark.
2. Click the gear icon next to the 'nRF 802.15.4 sniffer'.
3. Select the 802.15.4 channel.
4. Select the serial port associated with the board that you flashed the firmware on.
5. Click 'Start'.

## Wireshark configuration for Thread

### Decryption key

In order to decode packets exchanged on the Thread network it is necessary to configure the Wireshark to use correct decryption keys.
To set decryption keys go to `Edit -> Preferences... -> Protocols -> IEEE 802.15.4 -> Decryption Keys`.
Configure the following values:
* Decryption key: `00112233445566778899aabbccddeeff` (default value used by the Nordic Thread and Zigbee SDK examples)
* Decryption key index:`0`
* Key hash: `Thread hash`

### CoAP port configuration

Thread uses CoAP protocol on port 61631 for internal purposes. To correctly decode packets sent over that port you can either:
* apply the setting globally by editing CoAP protocol settings in `Preferences` and changing the `CoAP UDP port` value to `61631`.
* apply it on per-capture basis by adding an entry to `Analyze -> Decode as...`. Set `Field` column to `UDP port`, `Value` to `61631` and decode using CoAP dissector (`Current` column).

### 6loWPAN contexts

Go to 6loWPAN settings in `Preferences` window and add correct values. Contexts may vary depending on the Thread Network Data. Below values are used by Thread examples in nRF5 SDK.
* Context 0: `fdde:ad00:beef:0::/64`
* Context 1: `fd11:22::/64`

### Disable unwanted protocols (optional)

If Wireshark uses incorrect dissectors to decode a message you have an option to disable unwanted protocols. Go to `Analyze -> Enabled protocols` and uncheck unwanted protocols. Suggestions below.
* LwMesh
* ZigBee
* ZigBee Green Power

	
## Configuring Wireshark for Zigbee

To capture the data for Zigbee examples in SDK, you must manually configure Wireshark:
1. Press Ctrl + Shift + P to enter the Wireshark preferences.
2. Go to `Protocols -> Zigbee`.
3. Click the `Edit` button next to Pre-configured Keys. The Pre-configured Keys window appears.
4. Add two entries by clicking on the "+" button:
    - Key: `5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39`, Byte Order: Normal, Label: ZigbeeAlliance09
    - Key: `ab:cd:ef:01:23:45:67:89:00:00:00:00:00:00:00:00`, Byte Order: Normal, Label: Nordic Examples

## Custom Wireshark dissector
Custom wireshark dissector can be used to obtain additional informations from sniffer. Channel, RSSI and LQI can be displayed for every packet.

### Install Lua dissector
Copy the provided script to the appropriate directory (it can be found in `About Wireshark -> Folders -> Personal Lua Plugins`):
```
sudo cp nrf802154_sniffer/nrf802154_sniffer.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/
```
### Modify extcap script
Modify `nrf802154_sniffer.py`:

- Uncomment line 64:
    ```python
    DLT='user'
    ```
- Comment line 65:
    ```python
    #DLT='802.15.4'
    ```

## Troubleshooting

##### Sniffer capture hangs when another Wireshark process is started with nRF BLE sniffer extcap on Linux
This issue is caused by BLE sniffer extcap, which discovers connected sniffers during Wireshark startup by actively sending data to all serial ports.
Applications written for Linux primarily use advisory locking, which may be ignored by other applications.
Currently, the only way to avoid this issue is to disable the nRF BLE sniffer extcap by removing the executable flag:

```bash
sudo chmod -x <extcap_path>/nrf_sniffer.py
```

##### Sniffer capture hangs with `ModemManager` service enabled
On some occasions the `ModemManager` may send AT commands to the sniffer. To avoid it do one of the following:
* Disable `ModemManager` service
```bash
sudo systemctl stop ModemManager.service
sudo systemctl disable ModemManager.service
```
* Create `udev` rule (for `DEFAULT` or `PARANOID` policy only):
    1. Create new file in  in `/etc/udev/rules.d/99-nordic.rules` and write the text below:
        ```
        ACTION!="add", SUBSYSTEM!="usb_device", GOTO="rules_end"

        ATTR{idProduct}=="154a", ATTR{idVendor}=="1915", MODE="666"
        ATTR{idProduct}=="154a", ATTR{idVendor}=="1915", ENV{ID_MM_DEVICE_IGNORE}="1"

        LABEL="rules_end"
        ```
    2. Apply the new `udev` rules:
        ```bash
        udevadm trigger
        ```
    3. Verify that the settings have been successfully applied:
        ```bash
        udevadm info -q property -n /dev/ttyACMx
        ```
    4. Find the following values:
        ```
        ID_MM_CANDIDATE=0
        ID_MM_DEVICE_IGNORE=1
        ```
    5. Restart the `ModemManager`:
        ```bash
        sudo systemctl restart ModemManager
        ```
    __Note__: The above steps will not work if `STRICT` policy is used.

##### Sniffer interface does not appear in the Wireshark on Linux
You may not have sufficient permissions to access the serial device.
On Ubuntu you have to add the user to the `dialout` group.
To remedy this execute the following command:
```bash
sudo usermod -a -G dialout [user]
```
You may also have to add the user to the `wireshark` user group to start the capture:
```bash
sudo usermod -a -G wireshark [user]
```