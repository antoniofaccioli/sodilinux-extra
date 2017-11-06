import crypt # Interface to crypt(3), to encrypt passwords.
import getpass # To get a password from user input.
import spwd # Shadow password database (to read /etc/shadow).
import argparse

def login(user, password):
    """Tries to authenticate a user.
    Returns True if the authentication succeeds, else the reason
    (string) is returned."""
    try:
        enc_pwd = spwd.getspnam(user)[1]
        if enc_pwd in ["NP", "!", "", None]:
            return "user '%s' has no password set" % user
        if enc_pwd in ["LK", "*"]:
            return "account is locked"
        if enc_pwd == "!!":
            return "password has expired"
        # Encryption happens here, the hash is stripped from the
        # enc_pwd and the algorithm id and salt are used to encrypt
        # the password.
        if crypt.crypt(password, enc_pwd) == enc_pwd:
            return True
        else:
            return "incorrect password"
    except KeyError:
        return "user '%s' not found" % user
    return "unknown error"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", action='store', dest='user')
    parser.add_argument("-p", action='store', dest='psw')
    results = parser.parse_args()
    username = results.user
    password = results.psw
    status = login(username, password)
    if status == True:
        print('True')
    else:
        print('False')
