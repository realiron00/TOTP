import pyotp
import time
import base64

otp_key = base64.b32encode("test".encode())

now = int(time.time())
totp = pyotp.TOTP(otp_key, digits=10, interval=180)
otp1 = totp.at(now-180) # before 180s
otp2 = totp.at(now)
otp3 = totp.at(now+180) # after 180s
print(otp2) # OTP Password as of Current Time
print(totp.verify(otp2)) # True