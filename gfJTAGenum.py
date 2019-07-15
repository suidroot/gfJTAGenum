#!/usr/bin/python
'''
JTAG enumberator for the GreatFET


https://raw.githubusercontent.com/bkerler/JTAGenum/master/JTAGenum.ino

TODO: Implement brute force IR (brute_ir)

'''
import time
import sys
from greatfet import GreatFET

gf = GreatFET()

PINNAMES = ["J1_P4", "J1_P5", "J1_P6", "J1_P7", "J1_P8"]
#            "J1_P9", "J1_P10", "J1_P11", "J1_P12", "J1_P13"]
pins = []
PINSLEN = len(PINNAMES)

# Once you have found the JTAG pins you can define
# the following to allow for the boundary scan and
# irenum functions to be run. Define the values
# as the index for the pins[] array of the found
# jtag pin:
TCK = 0
TMS = 1
TDO = 2
TDI = 3
TRST = 4

# Pattern used for scan() and loopback() tests
PATTERN_LEN = 64

pattern = "0110011101001101101000010111001001"
# Use something more determinate when trying to find
# length of the DR register:
#static char pattern[PATTERN_LEN] = "1000000000000000000000000000000000";

# Max. number of JTAG enabled chips (MAX_DEV_NR) and length
# of the DR register together define the number of
# iterations to run for scan_idcode():
MAX_DEV_NR = 8
IDCODE_LEN = 32

# Target specific, check your documentation or guess
SCAN_LEN = 1890          # used for IR enum. bigger the better
IR_LEN = 5
# IR registers must be IR_LEN wide:
IR_IDCODE = "01100"       # always 011
IR_SAMPLE = "10100"       # always 101
IR_PRELOAD = IR_SAMPLE

#
# END USER DEFINITIONS
#

# TAP TMS states we care to use. NOTE: MSB sent first
# Meaning ALL TAP and IR codes have their leftmost
# bit sent first. This might be the reverse of what
# documentation for your target(s) show.
TAP_RESET = "11111"       # looping 1 will return
                            # IDCODE if reg available
TAP_SHIFTDR = "111110100"
TAP_SHIFTIR = "1111101100"  # -11111> Reset -0> Idle -1> SelectDR
                            # -1> SelectIR -0> CaptureIR -0> ShiftIR
# Ignore TCK, TMS use in loopback check:
IGNOREPIN = 0xFFFF
# Flags configured by UI:
VERBOSE = True
DELAY = False
DELAYUS = 5000  # 5 Milliseconds
PULLUP = True

reg_len = ""

################ Start Code ####################

def setup_pins():
    ''' Populate pins list with GF pin object '''
    for i in range(PINSLEN):
        print (i)
        pins.append(gf.gpio.get_pin(PINNAMES[i]))

    # TODO make move this here
    #for i in range(PINSLEN):
    #    pins[i].set_direction(gf.gpio.DIRECTION_IN)
        # if PULLUP set pull up on pin

def delay(d_time):
    ''' Delay time in MS '''
    d_time = d_time/1000
    time.sleep(d_time)

def init_pins(tck=IGNOREPIN, tms=IGNOREPIN, tdi=IGNOREPIN, ntrst=IGNOREPIN):
    ''' Initalize pins for test '''

    for i in range(PINSLEN):
        pins[i].set_direction(gf.gpio.DIRECTION_IN)
        # if PULLUP set pull up on pin

    if tck != IGNOREPIN:
        tck.set_direction(gf.gpio.DIRECTION_OUT)
    if tms != IGNOREPIN:
        tms.set_direction(gf.gpio.DIRECTION_OUT)
    if tdi != IGNOREPIN:
        tdi.set_direction(gf.gpio.DIRECTION_OUT)

    if ntrst != IGNOREPIN:
        ntrst.set_direction(gf.gpio.DIRECTION_OUT)
        ntrst.write(True)

def tap_state(tap_state_str, tck, tms):
    for i in tap_state_str:
        if DELAY:
            delay(DELAYUS)
        tck.write(False)
        if i == 1:
            tms.write(True)
        elif i == 0:
            tms.write(False)

        tck.write(True)

def pulse_tms(tck, tms, s_tms):
    ''' pulse tms pin '''
    if tck == IGNOREPIN:
        return
    tck.write(False)
    tms.write(s_tms)
    tck.write(True)

def pulse_tdi(tck, tdi, s_tdi):
    ''' Pulse tdi pin '''
    if DELAY:
        delay(DELAYUS)
    if tck != IGNOREPIN:
        tck.write(False)
    tdi.write(s_tdi)
    if tck != IGNOREPIN:
        tck.write(True)

def pulse_tdo(tck, tdo):
    ''' Pulse TCK then read TDO '''
    if DELAY:
        delay(DELAYUS)
    tck.write(False)
    tdo_read = tdo.read()
    tck.write(True)

    return tdo_read

# send pattern[] to TDI and check for output on TDO
# This is used for both loopback, and Shift-IR testing, i.e.
# the pattern may show up with some delay.
# return: 0 = no match
#         1 = match
#         2 or greater = no pattern found but line appears active
# if retval == 1, *reglen returns the length of the register '''
# TODO BROKEN, not maching ever
def check_data(pattern, iterations, tck, tdi, tdo, reg_len):
    ''' Send pattern out and check if it matches data read '''

    def booltobin(value):
        ''' convert bool to 1 or 0 '''
        if value is True:
            retval = 1
        elif value is False:
            retval = 0
        else:
            retval = 255

        return retval

    def bintobool(value):
        if int(value) == 1:
            retval = True
        elif int(value) == 0:
            retval = False
        else:
            retval = 255

        return retval

    w = 0
    plen = len(pattern)
    nr_toggle = 0 # count how often tdo is toggles
    rcv = ""
    tdo_prev = booltobin(tdo.read())
    retval = 255

    for i in range(iterations):

        pulse_tdi(tck, tdi, bintobool(pattern[w]))
        w += 1
        #if w > plen-1:
        #    w=0

        tdo_read = booltobin(tdo.read())
        nr_toggle += (tdo_read != tdo_prev)
        tdo_prev = tdo_read
        rcv += str(tdo_read)

        if w >= plen:
            #print ("rcv: " + rcv)
            if pattern == rcv:
                reg_len = w + 1 - plen
                retval = 1
                print ("MATCH")
                break
            else:
                rcv = ""
                w=0

    if retval == 1:
        pass
    elif nr_toggle > 1:
        reg_len = 0
        retval = nr_toggle
    else:
        reg_len = 0
        retval = 0

    return retval

def print_pins(tck, tms, tdo, tdi, ntrst):
    ''' Print pin names for pins '''

    if ntrst != IGNOREPIN:
        print ("ntrst: ", ntrst.name)
    print ("tck: ", tck.name)
    print ("tms: ", tms.name)
    print ("tdo: ", tdo.name)
    if tdi != IGNOREPIN:
        print ("tdi: ", tdi.name)

def scan():
    checkdataret = 0

    print ("==================================")
    print ("Starting scan to pattern", pattern)

    for ntrst in range(PINSLEN):
        for tck in range(PINSLEN):
            if tck == ntrst:
                continue

            for tms in range(PINSLEN):
                if tms == ntrst:
                    continue
                if tms == tck:
                    continue

                for tdo in range(PINSLEN):
                    if tdo == ntrst:
                        continue
                    if tdo == tck:
                        continue
                    if tdo == tms:
                        continue

                    for tdi in range(PINSLEN):
                        if tdi == ntrst:
                            continue
                        if tdi == tck:
                            continue
                        if tdi == tms:
                            continue
                        if tdi == tdo:
                            continue

                        if VERBOSE:
                            print("Checking: ", tck, tms, tdo, tdi, ntrst)
                            #print_pins(pins[tck], pins[tms], pins[tdo], pins[tdi], pins[ntrst])

                        init_pins(pins[tck], pins[tms], pins[tdi], pins[ntrst])
                        tap_state(TAP_SHIFTIR, pins[tck], pins[tms])
                        checkdataret = check_data(pattern, (2*PATTERN_LEN), pins[tck], \
                                pins[tdi], pins[tdo], reg_len)
                        if checkdataret == 1:
                            print ("FOUND!")
                            print_pins(pins[tck], pins[tms], pins[tdo], \
                                    pins[tdi], pins[ntrst])
                            print ("IR_length: ", reg_len)
                        elif checkdataret > 1:
                            print ("active")
                            print_pins(pins[tck], pins[tms], pins[tdo], \
                                    pins[tdi], pins[ntrst])
                            print ("bits toggled: ", checkdataret)

    print ("======================================")

def loopback_check():
    ''' Run loopback check on tdo and tdi '''

    checkdataret = 0

    print ("=================================")
    print ("Starting loopback check...")

    for tdo in range(PINSLEN):
        for tdi in range(PINSLEN):
            if tdi == tdo:
                continue

            if VERBOSE:
                print ("  tdo: ", pins[tdo].name)
                print ("  tdi: ", pins[tdi].name)

            init_pins(IGNOREPIN, IGNOREPIN, pins[tdi], IGNOREPIN)

            checkdataret = check_data(pattern, 2, IGNOREPIN, \
                    pins[tdi], pins[tdo], reg_len)
            if checkdataret == 1:
                print ("FOUND!")
                print ("tdo: ", pins[tdo].name)
                print ("tdi: ", pins[tdi].name)
                print ("reglen: ", reg_len)
            elif checkdataret > 1:
                print ("active")
                print ("tdo: ", pins[tdo].name)
                print ("tdi: ", pins[tdo].name)
                print ("bits toggled: ", checkdataret)
    print ("=============================")

def scan_idcode():
    ''' Scan for ID Codes '''

    idcodestr = "                                "
    idcode_i = 31
    idcodes = []

    print ("==================================")
    print ("Starting scan to pattern:", pattern)

    for ntrst in range(PINSLEN):
        for tck in range(PINSLEN):
            if tck == ntrst:
                continue

            for tms in range(PINSLEN):
                if tms == ntrst:
                    continue
                if tms == tck:
                    continue

                for tdo in range(PINSLEN):
                    if tdo == ntrst:
                        continue
                    if tdo == tck:
                        continue
                    if tdo == tms:
                        continue

                    for tdi in range(PINSLEN):
                        if tdi == ntrst:
                            continue
                        if tdi == tck:
                            continue
                        if tdi == tms:
                            continue
                        if tdi == tdo:
                            continue

                        if VERBOSE:
                            print_pins(tck, tms, tdo, tdi, ntrst)

                        init_pins(pins[tck], pins[tms], pins[tdi], pins[ntrst])

                        tap_state(TAP_RESET, pins[tck], pins[tms])
                        tap_state(TAP_SHIFTDR, pins[tck], pins[tms])

                        for i in range(MAX_DEV_NR):
                            idcodes[i] = 0
                            for j in range(IDCODE_LEN):
                                pulse_tdi(pins[tck], pins[tdi], 0)
                                tdo_read = pins[tdo].read()
                                if tdo_read:
                                    idcodes[i] |= 1 << j
                                if VERBOSE:
                                    print (tdo_read)
                            if VERBOSE:
                                print (idcodes[i])
                            if (not idcodes[i] & 1) or (idcodes[i] == 0xffffffff):
                                break
                        if i > 0:
                            print_pins(tck, tms, tdi, ntrst)
                            print ("  Devices: ", i)
                            print ("  0x", idcodes[i])

    print ("=================================================")

def shift_bypass():

    print ('''================================
    Starting shift of pattern through bypass...
    Assumes bypass is the default DR on reset.
    Hence, no need to check for TMS. Also, currently
    not checking for nTRST, which might not work
    ''')

    for tck in range(PINSLEN):
        for tdi in range(PINSLEN):
            if tdi == tck:
                continue

            for tdo in range(PINSLEN):
                if tdo == tck:
                    continue
                if tdo == tdi:
                    continue

                if VERBOSE:
                    print ("tck: ", pins[tck])
                    print ("tdi: ", pins[tdi])
                    print ("tdo: ", pins[tdo])

                init_pins(pins[tck], IGNOREPIN, pins[tdi], IGNOREPIN)
                checkdataret = check_data(pattern, 2, pins[tck], \
                        pins[tdi], pins[tdo], reg_len)

                if checkdataret == 1:
                    print ("FOUND! ")
                    print ("tdo: ", pins[tdo].name)
                    print ("tdi: ", pins[tdi].name)
                    print ("reglen: ", reg_len)
                elif checkdataret > 1:
                    print ("active ")
                    print ("tdo: ", pins[tdo].name)
                    print ("tdi: ", pins[tdo].name)
                    print ("bits toggled: ", checkdataret)

    print ("===============================")

def ir_state(state, tck, tms, tdi):
    '''
    ir_state()
    Set TAP to Reset then ShiftIR.
    Shift in state[] as IR value.
    Switch to ShiftDR state and end.
    '''

    tap_state(TAP_SHIFTIR, tck, tdi)

    for i in range(IR_LEN):
        # DELAY
        if i == IR_LEN-1:
            tms.write(True)

        pulse_tdi(tck, tdi, state-0)
        # TMS already set to 0 "shiftir" state to shift in bit to IR
        state += 1

    # a reset would cause IDCODE instruction to be selected again
    tap_state("1100", tck, tms) #  -1> UpdateIR -1> SelectDR -0> CaptureDR -0> ShiftDR

def sample(iterations, tck, tms, tdi, tdo, ntrst=IGNOREPIN):

    print ('''================================
Starting sample (boundary scan)...
''')
    init_pins(tck, tms, tdi, ntrst)
    ir_state(IR_SAMPLE, tck, tms, tdi)

    for i in range(iterations):
        print (pulse_tdo(tck, tdo))
        if i % 32 == 31: print (" ")
        if i % 128 == 127: print ("")

def set_pattern():
    ''' Manually Set a pattern '''

    # TODO input error checking
    pattern = input("Enter new pattern of 1's or 0's (terminate with new line):\r\n > ")
    print ("new pattern set to [" + pattern + "]")

def helpmenu():
    ''' Show Help Menu '''

    print ('''
Short and long form commands can be used.

SCANS
-----
s > pattern scan
    Scans for all JTAG pins. Attempts to set TAP state to
    DR_SHIFT and then shift the pattern through the DR.
p > pattern set
    currently: [''', pattern, ''']
i > idcode scan
    Assumes IDCODE is default DR on reset. Ignores TDI.
    Sets TAP state to DR_SHIFT and prints TDO to console
    when TDO appears active. Human examination required to
    determine if actual IDCODE is present. Run several
    times to check for consistancy or compare against
    active tdo lines found with loopback test.
b > bypass scan
    Assumes BYPASS is default DR on reset. Ignores TMS and
    shifts pattern[] through TDI/TDO using TCK for clock.

ERATTA
------
l > loopback check
    ignores tck,tms. if patterns passed to tdo pins are
    connected there is a short or a false-possitive
    condition exists that should be taken into account
r > pullups
    internal pullups on inputs, on/off. might increase
    stability when using a bad patch cable.
v > verbose
    on/off. print tdo bits to console during testing. will slow
    down scan.
d > delay
    on/off. will slow down scan.
- > delay -
    reduce delay by 1000us
+ > delay +
h > help

OTHER JTAG TESTS
----------------
Each of the following will not scan/find JTAG and require
that you manually set the JTAG pins. See their respective
call from the loop() function of code to set.

e > manually set pins
1 > pattern scan single
    runs a full check on one code-defined tdi<>tdo pair.
    look at the main()/loop() code to specify pins.
x > boundary scan
    checks code defined tdo for 4000+ bits.
    look at the main()/loop() code to specify pins.
''')

def set_pins():
    print ("Manually set the pins, in for mif Jx_Px\n\n")
    TCK = input("TCK: ")
    TMS = input("TMS: ")
    TDI = input("TDI: ")
    TDO = input("TDO: ")
    TRST = input("TRST: ")

    TCK = gf.gpio.get_pins(TCK)
    TMS = gf.gpio.get_pins(TMS)
    TDI = gf.gpio.get_pins(TDI)
    TDO = gf.gpio.get_pins(TDO)
    TRST = gf.gpio.get_pins(TRST)

def mainmenu():
    ''' Main Loop '''

    def single_scan():
        ''' Run single Scan '''
        init_pins(TCK, TMS, TDI, TDO)
        tap_state(TAP_SHIFTIR, TCK, TMS)
        if check_data(pattern, 2, TCK, TDI, TDO, None):
            print ("found pattern or other")
        else:
            print ("no pattern found")

    def boundry_scan():
        ''' Run sample Boundry Scan '''
        print ("Pins: " + print_pins(TCK, TMS, TDO, TDI, TRST))
        sample(SCAN_LEN+100, TCK, TMS, TDI, TDO, TRST)

    def decrement_delay():
        ''' Decrease Delay '''
        if (DELAYUS != 0 and DELAYUS > 1000):
            DELAYUS -= 1000
        elif (DELAYUS != 0 and DELAYUS <= 1000):
            DELAYUS -= 100

    def increment_delay():
        ''' Increate Delay '''
        if DELAYUS < 1000:
            DELAYUS += 100
        else:
            DELAYUS += 1000

    def verbose_toggle():
        ''' Toggle Verbose flag '''
        global VERBOSE
        VERBOSE = not VERBOSE
        print ("Verbose is set to " + str(VERBOSE))

    def pullup_toggle():
        ''' Toggle PULLUP flag '''
        global PULLUP
        PULLUP = not PULLUP
        print ("PULLUP is set to " + str(PULLUP))

    def delay_toggle():
        ''' Toggle Delay Flag '''
        global DELAY
        DELAY = not DELAY
        print ("DELAY is set to " + str(DELAY))

    def prog_quit():
        ''' Clean exit of script '''
        sys.exit(0)

    setup_pins()
    helpmenu()

    while 1:
        ##### Main Menu Block
        switcher = {
            "s" : scan,
            "1" : single_scan,
            "p" : set_pattern,
            "l" : loopback_check,
            "i" : scan_idcode,
            "b" : shift_bypass,
            "x" : boundry_scan,
            "v" : verbose_toggle,
            "d" : delay_toggle,
            "-" : decrement_delay,
            "+" : increment_delay,
            "r" : pullup_toggle,
            "e" : set_pins,
            "h" : helpmenu,
            "q" : prog_quit
        }
        userinput = input("> ")

        menu_func = switcher.get(userinput, lambda: "Invalid input")
        menu_func()

if __name__ == "__main__":
    mainmenu()
