import time
import base64
import hmac
import hashlib
import struct

#===============================================================================
# TOTP (Time-based One-time Password) Algorithm
#
# key: shared secret key
# time: time in seconds since the Epoch
# digits: number of digits in the OTP
# interval: time interval in seconds for OTP validity
#
# return: OTP as string
#===============================================================================
def totp(key, time, digits, interval):
    counter = time // interval
    return hotp(key, counter, digits)

#===============================================================================
# HOTP (HMAC-based One-time Password) Algorithm
#
# key: shared secret key
# counter: counter value
# digits: number of digits in the OTP
#
# return: OTP as string
#===============================================================================
def hotp(key, counter, digits):
    # Convert the counter to bytes
    counter_bytes = struct.pack(">Q", counter)

    # Decode the secret key
    key = base64.b32decode(key)

    # Compute the HMAC-SHA-1 hash
    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic Truncation
    offset = hmac_digest[-1] & 0x0F
    hash = hmac_digest[offset:offset+4]
    binary_code = struct.unpack(">I", hash)[0] & 0x7FFFFFFF

    # Generate an OTP of the specified length
    otp = str(binary_code % 10 ** digits)
    return otp.zfill(digits)

if __name__ == "__main__":
    otp_key = base64.b32encode("test".encode())
    now = int(time.time())
    otp1 = totp(otp_key, now, digits=10, interval=180)

    print(otp1) # OTP Password as of Current Time