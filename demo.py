import sys
from YeelightDimmer import YeelightDimmer

class MyYeelightDimmer(YeelightDimmer):
    def __init__(self, mac, key):
        super().__init__(mac, key)
        self.value = 0

    def draw(self, ruler = '-', pointer = '|'):
        picture = [ruler] * 61
        picture[30] = '0'
        picture[30 + self.value] = pointer
        print("[" + "".join(picture) + "] %03i" % self.value, end="\r", flush=True)

    def handleRotation(self, offset, button_down):
        self.value += offset
        if self.value <= -30:
            self.value = -30
        if self.value >= 30:
            self.value = 30

        if button_down:
            self.draw(ruler='=')
        else:
            self.draw()

    def handleClick(self):
        self.value = 0
        self.draw()

    def handleMultipleClicks(self, count):
        self.draw(pointer='o')

        if count == 3:
            self.unsubscribe()
            print("")
            return

    def handleLongPress(self, duration):
        self.draw(pointer='O')


def main():

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: %s <Dimmer MAC address> [beacon_key]" % sys.argv[0])
        print("\nIf beacon_key is missing, you have to retrieve it:")
        print("  1. Press the \"Pair\" button at the dimmer.")
        print("  2. Run this script without beacon_key parameter.")
        print("  3. Wait.")
        return

    mac = sys.argv[1]
    print("using mac %s" % mac)
    if len(sys.argv) > 2:
        beacon_key = sys.argv[2]
    else:
        beacon_key = None

    dimmer = MyYeelightDimmer('F8:24:41:C5:EE:A2', beacon_key)

    if beacon_key is None:
        print("! Press the \"Pair\" button at the dimmer...")
        if not dimmer.auth():
            return

        print("beacon_key: %s" % dimmer.beacon_key.hex())

    print("starting the demo. triple click to exit, single click to center the knob\n")
    dimmer.draw()
    dimmer.subscribe()


if __name__ == '__main__':
    main()