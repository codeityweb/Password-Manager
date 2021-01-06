import sqlite3
import hashlib
import base64
import string
import random

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def fernet_generate_passwordBased_key(masterkey):
    saltinbytes = bytes(masterkey, "utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=saltinbytes, iterations=100000, )
    key = base64.urlsafe_b64encode(kdf.derive(saltinbytes))
    f = Fernet(key)
    return f


def generateRandomPassword(length):
    digits = string.digits
    letters = string.ascii_letters
    punctuation = string.punctuation
    samplepass = letters + digits + punctuation + punctuation

    password = "".join(random.sample(samplepass, length))
    return password




class PassManager:

    def __init__(self):
        self.conn = sqlite3.connect("PasswordManager.db")
        query = '''Create Table if not exists PassStorage(
        site varchar(255)not null,
        username varchar(255) not null,
        password varchar(255) not null,
         email varchar(255))'''
        self.conn.execute(query)
        self.conn.commit()

    def createMasterUser(self):
        masterusername = input("Set Master UserName\n")
        masterkey = input("Set Master Password \n")
        salt = masterusername + masterkey
        # Remember the password because it cannot be restored
        # if  master password is lost all data access will be lost

        hashedpassword = hashlib.sha512((masterkey + salt).encode("utf-8")).hexdigest()

        try:

            # insert master user details now
            query = "Insert into PassStorage(site,username,password)values(?,?,?)"
            values = ("MasterUserID", masterusername, hashedpassword)
            self.conn.execute(query, values)
            self.conn.commit()
            return True
        except:
            return False

    def authenticate(self):
        masterusername = input("Enter Master UserName\n")
        masterkey = input("Enter  Master Password \n")
        salt = masterusername + masterkey
        hashedpassword = hashlib.sha512((masterkey + salt).encode("utf-8")).hexdigest()
        query = "select password from PassStorage where username=?"
        values = (masterusername,)
        cur = self.conn.execute(query, values)

        for row in cur:
            if row[0] == hashedpassword:
                return masterkey
            else:
                return "PDM"

    def storePassword(self):
        masterkey = self.authenticate()
        if masterkey is None:
            print("Username not present\n")
            return
        elif masterkey == "PDM":
            print("Passwords don't match\n")
            return
        else:
            site = input("Enter the name of the website\n\n")
            username = input("Enter the username you are using for that website\n\n")
            password = input("Enter the Corresponding password\n\n")
            email = input("Enter the email used for the website !! Blank if not Applicable\n\n")

            passwordinbytes = bytes(password, "utf-8")

            f = fernet_generate_passwordBased_key(masterkey)

            encryptedPassword = f.encrypt(passwordinbytes)
            # check if site is already present
            query = "Select site,username from PassStorage"
            cur = self.conn.execute(query)
            present = 0
            for qset in cur.fetchall():

                if site==qset[0] and username==qset[1]:
                    present = 1
                    break

            if present == 0 and (site!="" and username!="" and password!=""):
                query = "Insert into PassStorage(site,username,password,email)values(?,?,?,?)"
                values = (site, username, encryptedPassword, email)
                self.conn.execute(query, values)
                self.conn.commit()
                return 1
            else:
                return -1

    def showPasswords(self):
        masterkey = self.authenticate()
        if masterkey is None:
            print("Username not present\n")
            return
        elif masterkey == "PDM":
            print("Password don't match\n")
            return
        else:
            f = fernet_generate_passwordBased_key(masterkey)
            query = "select * from PassStorage where site is not ?"
            cur = self.conn.execute(query, ("MasterUserID",))
            print("  Site      |  Username      |      Password      |  Email Id")

            for row in cur:
                print(f'  {row[0]}      |  {row[1]}      |      {f.decrypt(row[2]).decode()}      |  {row[3]}')
                print("----------------------------------------------------------------------------------------")

    def updatePassword(self):
        masterkey = self.authenticate()
        if masterkey is None:
            return -1
        elif masterkey == "PDM":
            return -2
        else:
            site = input("Enter The Website Name\n\n")
            oldusername = input("Enter The Username used for website\n\n")
            query = "Select site,username from PassStorage"
            cur = self.conn.execute(query)
            present = 0
            for qset in cur.fetchall():
                if site==qset[0] and oldusername==qset[1]:
                    present = 1
                    break

            if present == 1:
                query = "update PassStorage set username=?, password=? where site=? and username=?"
                username = input("Enter the New UserName or Old as Applicable\n\n")
                password = input("Enter New Password\n\n")
                encryptedPassword = fernet_generate_passwordBased_key(masterkey).encrypt(bytes(password, "utf-8"))
                values = (username, encryptedPassword, site,oldusername)
                self.conn.execute(query, values)
                self.conn.commit()
                return 1
            else:
                return 0

    def deleteRecord(self):
        masterkey = self.authenticate()
        if masterkey is None:
            return -1
        elif masterkey == "PDM":
            return -2
        else:
            site = input("Enter The Website Name\n\n")
            username = input("Enter The Username used for website\n\n")
            query = "Select site,username from PassStorage"
            cur = self.conn.execute(query)
            present = 0
            for qset in cur.fetchall():
                if site==qset[0] and username==qset[1]:
                    present = 1
                    break

            if present == 1:
                query="delete from PassStorage where site=? and username=?"
                values=(site,username)
                self.conn.execute(query,values)
                self.conn.commit()
                return 1
            else:
                return 0




if __name__ == "__main__":
    ismasterpresent = False
    obj = PassManager()

    try:
        cur=obj.conn.execute("Select site from PassStorage")
        for row in cur:
            if row[0] == "MasterUserID":
                ismasterpresent=True
                break

        if ismasterpresent:
                while (True):
                    print("-------------------")
                    flag = input(
                        '''Enter your Choice\n
                        1.To Generate Random Password\n
                        2.To Store PassWord\n 
                        3. To See All Passwords\n 
                        4.To Update Site Password\n 
                        5.Delete record\n 
                        6. To Exit\n''')
                    print("-------------------")
                    if flag == "6":
                        break

                    elif flag == "1":
                        size = input('''Enter the length of password required.\n''')
                        try:
                            size = int(size)
                            randompass = generateRandomPassword(size)
                            print("Password is :", randompass)
                        except:
                            print("Enter Numerical Value\n")

                    elif flag == "2":

                        result = obj.storePassword()
                        if result == 1:
                            print("Password Stored SuccessFully")
                        else:
                            print('''Site May be already present!
                             check the storage or
                              fill all details properly''')

                    elif flag == "3":
                        obj.showPasswords()

                    elif flag == "4":
                        result = obj.updatePassword()
                        if result == 1:
                            print("Password updated SuccessFully")
                        elif result == -1:
                            print("User is not Present")
                        elif result == -2:
                            print("Password Don't Match")
                        else:
                            print('''The site is not present
                             or username is not present
                              ,you can add the site''')
                    elif flag=="5":
                        result = obj.deleteRecord()
                        if result == 1:
                            print("Record deleted!")
                        elif result == -1:
                            print("User is not Present")
                        elif result == -2:
                            print("Password Don't Match")
                        else:
                            print("Site is not present")

                    else:
                        print("Enter proper choice\n")

        else:
            result = obj.createMasterUser()
            if result:
                print('''Master User Created 
                Do not Forget Password 
                Else you will loose all the data\n''')
            else:
                print("Master User May be Present\n ")


    except:
        exit(1)