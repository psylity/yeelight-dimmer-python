from Cryptodome.Cipher import AES
from bluepy.btle import UUID, Peripheral, DefaultDelegate, Scanner
import struct
import random
import time

class XiaomiEncryption(object):

    @staticmethod
    def _cipherInit(key):
        perm = bytearray()
        for i in range(0, 256):
            perm.extend(bytes([i & 0xff]))
        keyLen = len(key)
        j = 0
        for i in range(0, 256):
            j += perm[i] + key[i % keyLen]
            j = j & 0xff
            perm[i], perm[j] = perm[j], perm[i]
        return perm

    @staticmethod
    def mixA(mac, productID):
        return bytes([mac[0], mac[2], mac[5], (productID & 0xff), (productID & 0xff), mac[4], mac[5], mac[1]])

    @staticmethod
    def mixB(mac, productID):
        return bytes([mac[0], mac[2], mac[5], ((productID >> 8) & 0xff), mac[4], mac[0], mac[5], (productID & 0xff)])

    @staticmethod
    def _cipherCrypt(input, perm):
        index1 = 0
        index2 = 0
        output = bytearray()
        for i in range(0, len(input)):
            index1 = index1 + 1
            index1 = index1 & 0xff
            index2 += perm[index1]
            index2 = index2 & 0xff
            perm[index1], perm[index2] = perm[index2], perm[index1]
            idx = perm[index1] + perm[index2]
            idx = idx & 0xff
            outputByte = input[i] ^ perm[idx]
            output.extend(bytes([outputByte & 0xff]))

        return output

    @staticmethod
    def cipher(key, input):
        perm = XiaomiEncryption._cipherInit(key)
        return XiaomiEncryption._cipherCrypt(input, perm)


    # AES
    @staticmethod
    def decryptMiBeaconV2(key, data):
        # prepare aes key (12b -> 16b)
        key_1 = key[0:6]
        key_2 = bytes.fromhex("8d3d3c97")
        key_3 = key[6:]
        key = b"".join([key_1, key_2, key_3])

        # extract packet fields
        xiaomi_mac_reversed = data[7:13]
        framectrl_data = data[2:4]
        device_type = data[4:6]
        encrypted_payload = data[13:]

        packet_id = data[6:7]
        payload_counter = b"".join([packet_id,  encrypted_payload[-4:-1]])

        # prepare nonce
        nonce = b"".join([framectrl_data, device_type, payload_counter, xiaomi_mac_reversed[:-1]])

        cipherpayload = encrypted_payload[:-4]

        # AES decrypt
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x11")
        return cipher.decrypt(cipherpayload)


class YeelightDimmer(object):
    PRODUCT_ID = 950
    UUID_PRIMARY_SERVICE = "fe95" # XIAOMI Inc.

    XIAOMI_KEY1 = bytes([0x90, 0xCA, 0x85, 0xDE])
    XIAOMI_KEY2 = bytes([0x92, 0xAB, 0x54, 0xFA])

    HANDLE_AUTH_INIT = 19
    HANDLE_AUTH = 3
    HANDLE_BEACON_KEY = 25
    HANDLE_READ_FIRMWARE_VERSION = 10

    SUBSCRIBE_TRUE = bytes([0x01, 0x00])

    def __init__(self, mac, beacon_key = None):
        self.mac = mac.lower()

        rmac = [x for x in bytes.fromhex(mac.replace(':',''))]
        rmac.reverse()
        self.reversed_mac = rmac

        self.token = bytes([random.randint(0,255) for i in range(12)])

        self.beacon_key = None
        if not beacon_key is None:
            self.beacon_key = bytes.fromhex(beacon_key)

        self.prev_packet_id = None
        self.auth_can_pass = False

    def auth(self):
        self.auth_can_pass = False

        self.onConnectionStart()
        if not self._connect():
            self.onConnectionFail()
            return
        self.onConnectionDone()

        self.onAuthStart()
        descriptors = self.service.getDescriptors()
        self.peripheral.writeCharacteristic(self.HANDLE_AUTH_INIT, self.XIAOMI_KEY1, True)
        descriptors[1].write(self.SUBSCRIBE_TRUE, True)

        self.peripheral.writeCharacteristic(self.HANDLE_AUTH, XiaomiEncryption.cipher(XiaomiEncryption.mixA(self.reversed_mac, self.PRODUCT_ID), self.token), "true")

        self.peripheral.waitForNotifications(10.0) # 10 sec auth timeout

        if not self.auth_can_pass: # this flag should be changed in handleNotification
            self.onAuthFail()
            return

        self.peripheral.writeCharacteristic(self.HANDLE_AUTH, XiaomiEncryption.cipher(self.token, self.XIAOMI_KEY2), True)
        
        # have to read firmware version to complete auth
        self.firmware_version = XiaomiEncryption.cipher(self.token, self.peripheral.readCharacteristic(self.HANDLE_READ_FIRMWARE_VERSION)).decode()

        self.beacon_key = bytes(XiaomiEncryption.cipher(self.token, self.peripheral.readCharacteristic(self.HANDLE_BEACON_KEY)))
        self.onAuthDone(self.beacon_key)
        return True

    def subscribe(self):
        self.scanner_run = True
        scanner = Scanner().withDelegate(self)
        self.scanner = scanner
        scanner.start()

        while self.scanner_run: # main loop
            scanner.process(1) # 1 seconds timeout

        scanner.stop()

    def unsubscribe(self):
        self.scanner_run = False

    def _connect(self):
        try:
            self.peripheral = Peripheral(deviceAddr=self.mac)
            self.peripheral.setDelegate(self)
            self.service = self.peripheral.getServiceByUUID(self.UUID_PRIMARY_SERVICE)
        except:
            return False
        return True

    def handleNotification(self, cHandle, data):
        if cHandle == self.HANDLE_AUTH:
            decrypted_token = XiaomiEncryption.cipher(XiaomiEncryption.mixB(self.reversed_mac, self.PRODUCT_ID),
                               XiaomiEncryption.cipher(XiaomiEncryption.mixA(self.reversed_mac, self.PRODUCT_ID), data))

            if (decrypted_token != self.token):
                return # raise Exception("Authentication failed.")

            self.auth_can_pass = True

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if dev.addr != self.mac:
            return

        for (id, decsr, data) in dev.getScanData():
            if id != 22:
                continue

            data = bytes.fromhex(data)
            if len(data) < 23:
                continue

            packet_id = data[6]

            if packet_id == self.prev_packet_id:
                continue

            self.prev_packet_id = packet_id

            decrypted = XiaomiEncryption.decryptMiBeaconV2(self.beacon_key, data)

            # The decrypted payload can be read as follows.
            # 0110 = Button (= type of message according to the MiBeacon protocol)
            # 03 = length of data
            # 00 = value1
            # ff = value2
            # 04 = state

            fields = struct.unpack(">HBbbB", decrypted[0:6])

            if fields[0] != 0x0110: # unknown packet, skip
                continue

            if fields[1] != 3:
                # never seen such packet, dont know how to handle
                continue

            self.onDataPacket(fields[2], fields[3], fields[4], decrypted)

    def onDataPacket(self, value1, value2, button_state, raw):
        if button_state == 4:
            if value1 == 0:
                return self.onRotate(value2, False)

            if value2 == 0:
                return self.onRotate(value1, True)

            if value1 != 0 and value2 != 0:
                # both rotated with button pressed and not.
                # occures only near with button_pressed event
                # print(value1, value2, button_state)
                return

        if button_state == 3:
            if value1 == 0:
                if value2 == 1:
                    return self.onClick()
                else:
                    return self.onMultipleClicks(value2)

            if value1 == 1:
                return self.onLongPress(value2)

        raise Exception("Unhandled dimmer packet: 0x%s" % raw.hex())

    # methods to override
    def onConnectionStart(self):
        pass

    def onConnectionDone(self):
        pass

    def onConnectionFail(self):
        pass

    def onAuthStart(self):
        pass

    def onAuthDone(self, beacon_key):
        pass

    def onAuthFail(self):
        pass

    # dimmer events
    def onRotate(self, offset, button_down):
        pass

    def onClick(self):
        pass

    def onMultipleClicks(self, count):
        pass

    def onLongPress(self, duration):
        pass