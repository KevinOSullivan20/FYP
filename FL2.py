import re
from email.parser import HeaderParser
import time
from tkinter import filedialog
from tkinter import *
import os
import sqlalchemy
import pymysql
import psycopg2
import mysql.connector.locales.eng
import sqlalchemy.sql.default_comparator
from sqlalchemy import *
import pandas as pd
import mysql.connector
from colored import fg, bg, attr
reset = attr('reset')
red = fg('red')
orange = fg('208')
green = fg('green')

#global msg
# Count variables initalised
spfCount = 0
spfPassCount = 0
spfNeutralCount = 0
spfFailCount = 0

dkimCount = 0
dkimPassCount = 0
dkimFailCount = 0

dmarcCount = 0
dmarcPassCount = 0
dmarcFailCount = 0

totalChecksCount = 0
totalChecksFailCount = 0

AttachmentCount = 0
ShellAttchCount = 0
pdfAttachCount = 0
pngAttachCount = 0
jpegAttachCount = 0
zipAttachCount = 0


malwareChance = ''
otherRiskChance = ''


def createtbl():
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print('')
    print('Please enter the information requested below to connect to a MySql database.')
    print('The table you create will be populated with IP addresses flagged as high risk\nduring the analysis process.')
    print('')
    print(
        '_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    global host
    global port
    global user
    global passwd
    global dbname
    global table
    host = input('Hostname(e.g. localhost): ')
    port = input('Port(e.g. 3306): ')
    user = input('Username: ')
    passwd = input('Password: ')
    dbname = input('Database name: ')
    table = input('Table name(To create): ')


    try:

        connection = mysql.connector.connect(host=host,
                                             user=user,
                                             password=passwd,
                                             database=dbname,
                                             use_pure=True,
                                             port=port,
                                             )
        cursor = connection.cursor()
        connection.connect()

        if connection.is_connected():
            db_Info = connection.get_server_info()
            print(green + "Connected to MySQL Server version " + reset, db_Info)
            cursor.execute("select database();")
            record = cursor.fetchone()
            print(green + "You're connected to the database: " + reset, record)

            mySql_Create_Table_Query = """CREATE TABLE IF NOT EXISTS %s( 
                                                Id int(20) NOT NULL AUTO_INCREMENT,
                                                Flagged_IP varchar(25),
                                                Sender_Address varchar(140),
                                                Receiving_Address varchar(140),
                                                Time_Received varchar(140),
                                                PRIMARY KEY (Id)) """ % table

            cursor.execute("""
                   SELECT COUNT(*)
                   FROM information_schema.tables
                   WHERE table_name = '{0}'
                   """.format(table.replace('\'', '\'\'')))
            if cursor.fetchone()[0] == 1:
                print(red + 'The table ' + table + ' already exists in the database ' + dbname + '.' + ' Please enter another table name.' + reset)
                createtbl()
            else:
                result = cursor.execute(mySql_Create_Table_Query)
                print(green + 'The table '+table + ' was created successfully in the database ' + dbname + reset)



    except mysql.connector.ProgrammingError as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        createtbl()
    except mysql.connector.Error as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        createtbl()
    except OSError as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        createtbl()
    except:
        print(red + 'An exception has occurred, Please ensure your MySql server is running on the host ' + host +
              ' on the specified port ' + port + '.' + ' Please also verify that the other information entered is correct. '
                                                       'For more information please refer to the help page.' + reset)
        createtbl()
    return host, port, user, passwd, dbname, table




def tbl_exists():
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print('')
    print('Please enter the information requested below to connect to a MySql database')
    print('The table you choose will be populated with IP addresses flagged as high risk\nduring the analysis process.')
    print('')
    print(orange + 'NOTE: You must use a table created by this application\nor a table created with the values specified in the help page.' + reset)
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    global host
    global port
    global user
    global passwd
    global dbname
    global table
    host = input('Hostname(e.g. localhost): ')
    port = input('Port(e.g. 3306): ')
    user = input('Username: ')
    passwd = input('Password: ')
    dbname = input('Database name: ')
    table = input('Table name(Existing'+orange+'[Created by this application]'+ reset+'): ')


    try:

        connection = mysql.connector.connect(host=host,
                                             user=user,
                                             password=passwd,
                                             database=dbname,
                                             use_pure=True,
                                             port=port,
                                             )
        cursor = connection.cursor()
        connection.connect()

        if connection.is_connected():
            db_Info = connection.get_server_info()
            print(green + "Connected to MySQL Server version " + reset, db_Info)
            cursor.execute("select database();")
            record = cursor.fetchone()
            print(green + "You're connected to the database: "+ reset, record)

            cursor.execute("""
                              SELECT COUNT(*)
                              FROM information_schema.tables
                              WHERE table_name = '{0}'
                              """.format(table.replace('\'', '\'\'')))
            if cursor.fetchone()[0] != 1:
                print(red + 'The table ' + table + ' does not exists in the database ' + dbname + '.' + '\nPlease enter another table name or use this program to create the table. ' + table + reset)
                tbl_exists()
            else:
                print(green + 'Using existing table ' + table + reset)

    except mysql.connector.ProgrammingError as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        tbl_exists()
    except mysql.connector.InterfaceError as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        tbl_exists()
    except mysql.connector.DatabaseError as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        tbl_exists()
    except mysql.connector.Error as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        tbl_exists()
    except OSError as e:
        print(red + 'An exception occurred: {}'.format(e) + reset)
        tbl_exists()
    except:
        print(red +'An exception has occurred, Please ensure your MySql server is running on the host ' +host +
              ' on the specified port ' +port +'.'+' Please also verify that the other information entered is correct. '
                                               'For more information please refer to the help page.' + reset)
        tbl_exists()
    return host, port, user, passwd, dbname, table





def connectdb():
    engine = sqlalchemy.create_engine('mysql+pymysql://' + str(user) + ':' + str(passwd) +'@'+ str(host) + ':' + str(port) + '/'+ str(dbname))
    return engine




def createdf():
    timestamp = msg['Date']
    snd_address = msg['From']
    rcv_address = msg['To']
    con = connectdb()
    ip = clientip()

    data = pd.DataFrame({
        'Flagged_IP': [ip],
        'Sender_Address': [snd_address],
        'Receiving_Address': [rcv_address],
        'Time_Received': [timestamp],
    })

    data.to_sql(name=table, con=con, if_exists='append', chunksize=1000, index=False)



def openfile():
    import tkinter as tk
    from tkinter.filedialog import askopenfilename
    root = tk.Tk()
    root.withdraw()
    filename = askopenfilename(
                           filetypes =(("Text File", "*.txt"),("All Files","*.*")),
                           title = "Choose an email to analyse")

    return filename

def out():
    print('Performing header analysis..')
    print('\n')
    time.sleep(1)
    print('The receiving address is: \n' + (msg['To']))
    print('\n')
    print('The sender address is: \n' + (msg['From']))
    print('\n')
    print('Created at: \n ' + (msg['Date']))
    print('\n')
    print('The return path is: \n ' + (msg['Return-Path']))
    print('\n')


def parse():
    global msg
    parser = HeaderParser()
    try:
        msg = parser.parse(open(openfile()))
    except FileNotFoundError:
        print("No file was selected, Please re-run the program and choose a file.")
        exit()
    else:
        out()
    return msg

def parsemulti():
    global msg
    global spfCount
    global spfPassCount
    global spfFailCount
    global dkimCount
    global dkimPassCount
    global dkimFailCount
    global dmarcCount
    global dmarcPassCount
    global dmarcFailCount
    global totalChecksCount
    global totalChecksFailCount
    global AttachmentCount
    global ShellAttchCount
    global pdfAttachCount
    global pngAttachCount
    global jpegAttachCount
    global zipAttachCount
    root = Tk()
    root.withdraw()
    folder_selected = filedialog.askdirectory(title='Choose the directory where you have your email files stored')

    print(folder_selected)
    parser = HeaderParser()
    num_files = 0
    for path, dirs, files in os.walk(folder_selected):
        for f in files:
            num_files += 1
            spfCount = 0
            spfPassCount = 0
            spfFailCount = 0

            dkimCount = 0
            dkimPassCount = 0
            dkimFailCount = 0

            dmarcCount = 0
            dmarcPassCount = 0
            dmarcFailCount = 0

            totalChecksCount = 0
            totalChecksFailCount = 0

            AttachmentCount = 0
            ShellAttchCount = 0
            pdfAttachCount = 0
            pngAttachCount = 0
            jpegAttachCount = 0
            zipAttachCount = 0
            msg = (parser.parse(open(os.path.join(folder_selected, f))))
            print('')
            print('=================================================================')
            print('Email Number: ' + str(num_files))
            print('=================================================================')
            print('')

            out()
            spf()
            dkim()
            dmarc()
            attach()
            attachtype()
            clientip()
            risk()

def parsemulti_no_bl():
    global msg
    global spfCount
    global spfPassCount
    global spfFailCount
    global dkimCount
    global dkimPassCount
    global dkimFailCount
    global dmarcCount
    global dmarcPassCount
    global dmarcFailCount
    global totalChecksCount
    global totalChecksFailCount
    global AttachmentCount
    global ShellAttchCount
    global pdfAttachCount
    global pngAttachCount
    global jpegAttachCount
    global zipAttachCount
    root = Tk()
    root.withdraw()
    folder_selected = filedialog.askdirectory(title='Choose the directory where you have your email files stored')

    print(folder_selected)
    parser = HeaderParser()
    num_files = 0
    #headers = parser.parsestr(msg.as_string())
    for path, dirs, files in os.walk(folder_selected):
        for f in files:
            num_files += 1
            spfCount = 0
            spfPassCount = 0
            spfFailCount = 0

            dkimCount = 0
            dkimPassCount = 0
            dkimFailCount = 0

            dmarcCount = 0
            dmarcPassCount = 0
            dmarcFailCount = 0

            totalChecksCount = 0
            totalChecksFailCount = 0

            AttachmentCount = 0
            ShellAttchCount = 0
            pdfAttachCount = 0
            pngAttachCount = 0
            jpegAttachCount = 0
            zipAttachCount = 0
            msg = (parser.parse(open(os.path.join(folder_selected, f))))
            print('')
            print('=================================================================')
            print('Email Number: ' + str(num_files))
            print('=================================================================')
            print('')

            out()
            spf()
            dkim()
            dmarc()
            attach()
            attachtype()
            clientip()
            risk_no_bl()



################################################################################
##########################SPF Checks############################################
# Regex searches for the pattern spf=pass in the email header
def spf():
    global spfCount
    global spfPassCount
    global spfNeutralCount
    global totalChecksCount
    global spfFailCount
    global totalChecksFailCount
    patternSPF = re.compile(r'spf=')
    patternSPFpass = re.compile(r'spf=pass')
    patternSPFfail = re.compile(r'spf=fail')
    patternSPFneutral = re.compile(r'spf=neutral')

    spfMatches = patternSPF.finditer(str(msg))
    spfPassMatches = patternSPFpass.finditer(str(msg))
    spfFailMatches = patternSPFfail.finditer(str(msg))
    spfNeutralMatches = patternSPFneutral.finditer(str(msg))

    # For loop counts the number of matches
    for match in spfMatches:
        spfCount += 1
        totalChecksCount += 1

    for match in spfPassMatches:
        spfPassCount += 1
        #totalChecksCount += 1

    for match in spfFailMatches:
        spfFailCount += 1
        totalChecksFailCount += 1
        #totalChecksCount += 1

    for match in spfNeutralMatches:
        spfNeutralCount +=1

    # If statement checks if the number of times the string 'spf=pass' was found was greater than 1
    # If yes then spf check passed
    if spfCount >= 1 & spfPassCount >= 1 & spfFailCount == 0:
        print(str(spfCount) + ' SFP checks were performed on the email ' + str(spfFailCount) + ' SPF Checks failed')
    elif spfCount == 0:
        print('SPF Checks do not appear to have been performed on this email')
    if spfNeutralCount >=1:
        print(str(spfNeutralCount) + ' SPF check(s) returned a value of neutral')
    else:
        print(str(spfCount) + ' SFP checks were performed on the email ' + str(spfFailCount) + ' SPF Checks failed')


#################################################################################
##########################DKIM Checks############################################
def dkim():
    global dkimCount
    global dkimPassCount
    global dkimFailCount
    global totalChecksCount
    global totalChecksFailCount
    patternDKIM = re.compile(r'dkim=')
    patterndkimPass = re.compile(r'dkim=pass')
    patterndkimFail = re.compile(r'dkim=fail')

    dkimMatches = patternDKIM.finditer(str(msg))
    dkimPassMatches = patterndkimPass.finditer(str(msg))
    dkimFailMatches = patterndkimFail.finditer(str(msg))

    for match in dkimMatches:
        dkimCount += 1
        totalChecksCount += 1

    for match in dkimPassMatches:
        dkimPassCount += 1
        #totalChecksCount += 1

    for match in dkimFailMatches:
        dkimFailCount += 1
        totalChecksFailCount += 1
        #totalChecksCount += 1

    if dkimCount >= 1 & dkimPassCount >= 1 & dkimFailCount == 0:
        print(str(dkimCount) + ' DKIM checks were performed on the email ' + str(dkimFailCount) + ' DKIM Checks failed')
    elif dkimCount == 0:
        print('DKIM Checks do not appear to have been performed on this email')
    else:
        print(str(dkimCount) + ' DKIM checks were performed on the email ' + str(dkimFailCount) + ' DKIM Checks failed')





#################################################################################
##########################DMARC Checks############################################
def dmarc():
    global dmarcCount
    global dmarcPassCount
    global dmarcFailCount
    global totalChecksCount
    global totalChecksFailCount

    patternDMARC = re.compile(r'dmarc=')
    patternDMARCPass = re.compile(r'dmarc=pass')
    patternDMARCFail = re.compile(r'dmarc=fail')

    dmarcMatches = patternDMARC.finditer(str(msg))
    dmarcPassMatches = patternDMARCPass.finditer(str(msg))
    dmarcFailMatches = patternDMARCFail.finditer(str(msg))

    for match in dmarcMatches:
        dmarcCount += 1
        totalChecksCount += 1

    for match in dmarcPassMatches:
        dmarcPassCount += 1
        #totalChecksCount += 1

    for match in dmarcFailMatches:
        dmarcFailCount += 1
        totalChecksFailCount += 1
        #totalChecksCount += 1

    if dmarcCount >= 1 and dmarcPassCount >= 1 and dmarcFailCount == 0:
        print(str(dmarcCount) + ' DMARC checks were performed on the email ' + str(dmarcFailCount)
              + ' DMARC Checks failed')
    elif dmarcCount == 0:
        print('DMARC Checks do not appear to have been performed on this email')
    else:
        print(str(dmarcCount) + ' DMARC checks were performed on the email ' + str(
            dmarcFailCount) + ' DMARC Checks failed')
    print('\n')

######################################################################################
###########################Attachement Check##########################################
def attach():
    global AttachmentCount
    patternAttachement = re.compile(r'Content-Disposition: attachment')
    AttachementMatches = patternAttachement.finditer(str(msg))

    for match in AttachementMatches:
        AttachmentCount +=1

    if AttachmentCount >= 1:
        print('The email contains ' + str(AttachmentCount) +' attachment(s)')
    else:
        print('The email does not contain any attachments')



#######################################################################################
#######################Attachment Type Check###########################################
def attachtype():
    global ShellAttchCount
    global pdfAttachCount
    global pngAttachCount
    global jpegAttachCount
    global zipAttachCount
    global AttachmentCount
    #******Shell Attachement******
    patternShell = re.compile(r'Content-Type: application/x-sh')
    shellMatches = patternShell.finditer(str(msg))

    for match in shellMatches:
        ShellAttchCount +=1

    if ShellAttchCount >= 1:
        print('The email contains ' + str(ShellAttchCount) + ' Shell script attachment(s)')

    #******PNG Attachement******
    patternPNG = re.compile(r'Content-Type: image/png')
    PNGMatches = patternPNG.finditer(str(msg))

    for match in PNGMatches:
        pngAttachCount +=1

    if pngAttachCount >= 1:
        print('The email contains ' + str(pngAttachCount) + ' PNG attachment(s)')

    #******JPEG Attachement******
    patternJPEG = re.compile(r'Content-Type: image/jpeg')
    JPEGMatches = patternJPEG.finditer(str(msg))

    for match in JPEGMatches:
        jpegAttachCount +=1

    if jpegAttachCount >= 1:
        print('The email contains ' + str(jpegAttachCount) + ' JPEG attachment(s)')
    print('\n')
    #******PDF Attachement******
    patternPDF = re.compile(r'Content-Type: application/pdf')
    PDFMatches = patternPDF.finditer(str(msg))

    for match in PDFMatches:
        pdfAttachCount +=1

    if pdfAttachCount >= 1:
        print('The email contains ' + str(pdfAttachCount) + ' PDF attachment(s)')

    #******ZIP Attachement******
    patternZIP = re.compile(r'Content-Type: application/x-zip-compressed')
    ZIPMatches = patternZIP.finditer(str(msg))

    for match in ZIPMatches:
        zipAttachCount +=1

    if zipAttachCount >= 1:
        print('The email contains ' + str(zipAttachCount) + ' ZIP attachment(s)')

    if AttachmentCount >= 1 and ShellAttchCount == 0 and pdfAttachCount == 0 and jpegAttachCount == 0 and pngAttachCount == 0 and zipAttachCount == 0:
        print('The attachment type is unknown')



###################################################################################
####################### Identify Client IP#########################################
def clientip():
        patternIP = re.compile(r'client-ip=(.*);')
        IPMatches = patternIP.finditer(str(msg))
        for match in IPMatches:
            print('Associated client IP = ' + str(match.group(1)))
            ip = match.group(1)

            return ip

        print('\n')


##################################################################################
#########################Risk Assessement#########################################

def risk():
    def info():
        print('INFO: ' + str(totalChecksFailCount) + ' of the ' + str(totalChecksCount) + ' checks performed failed')
        print('The email contains ' + str(AttachmentCount) + ' attachment(s)')
        print('Malware chance - ' + malwareChance)
        print('Risk of malware-less phishing or spear phishing attempt - ' + otherRiskChance)

    def blacklistcheck():
        if malwareChance == red + 'HIGH' + reset or otherRiskChance == red + 'HIGH' + reset or malwareChance == red + 'VERY HIGH' + reset or otherRiskChance == red + 'VERY HIGH' + reset:
           createdf()

    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = green + 'LOW' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = red + 'VERY HIGH' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount >= 1:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = green + 'LOW' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = orange + 'MEDIUM' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = red + 'HIGH' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount >= 1 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'VERY HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = red + 'HIGH' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount == 0 and AttachmentCount >= 1:
        malwareChance = orange + 'MEDIUM' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()
        blacklistcheck()

    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()
        blacklistcheck()

    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount >= 1:
        malwareChance = orange + 'MEDIUM' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()
        blacklistcheck()

    elif spfNeutralCount >=1:
        snd_address = msg['From']
        print(str(spfNeutralCount) + ' SPF checks returned a value of neutral. \n' + 'This means ' + clientip() + ' is neither permitted nor denied by best guess record for the domain of ' + snd_address + '\nThis may result in a ' + orange + 'false negative.' + reset + ' For this reason, the overall risk rating for this email is: ' + orange + 'MEDIUM' + reset)


def risk_no_bl():
    def info():
        print('INFO: ' + str(totalChecksFailCount) + ' of the ' + str(totalChecksCount) + ' checks performed failed')
        print('The email contains ' + str(AttachmentCount) + ' attachment(s)')
        print('Malware chance - ' + malwareChance)
        print('Risk of malware-less phishing or spear phishing attempt - ' + otherRiskChance)

    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = green + 'LOW' + reset
        info()


    if spfFailCount >= 1 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = red + 'VERY HIGH' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount >= 1:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = green + 'LOW' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = orange + 'MEDIUM' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = red + 'HIGH' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()

    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()


    if spfFailCount >= 1 and dmarcFailCount >= 1 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()


    if spfFailCount >= 1 and dmarcFailCount >= 1 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'VERY HIGH' + reset
        info()


    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount >= 1:
        malwareChance = red + 'HIGH' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()


    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount >= 1 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = red + 'HIGH' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount == 0 and AttachmentCount >= 1:
        malwareChance = orange + 'MEDIUM' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()


    if spfFailCount == 0 and dmarcFailCount >= 1 and dkimFailCount == 0 and AttachmentCount == 0:
        malwareChance = green + 'LOW' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()


    if spfFailCount >= 1 and dmarcFailCount == 0 and dkimFailCount == 0 and AttachmentCount >= 1:
        malwareChance = orange + 'MEDIUM' + reset
        otherRiskChance = orange + 'MEDIUM' + reset
        info()

    elif spfNeutralCount >=1:
        snd_address = msg['From']
        print(str(spfNeutralCount) + ' SPF checks returned a value of neutral. \n' + 'This means ' + clientip() + ' is neither permitted nor denied by best guess record for the domain of ' + snd_address + '\nThis may result in a ' + orange + 'false negative.' + reset + ' For this reason, the overall risk rating for this email is: ' + orange + 'MEDIUM' + reset)






