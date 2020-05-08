#Performs SPF, DKIM and DMARC checks.
#Checks if the email has an attachment
#Checks type of attachment, shell, png, jpeg, pdf and zip detected
#Identifies client IP
#Performs Risk assessment
#Performs analysis on one email
#Performs analysis on Multiple emails
#Writes the associed client IP to a MySql Database for emails flagged as high risk during the risk assessment process.
#Database Functionality: Connect to MySql database, Create table, use existing table

import FL2
from colored import fg, bg, attr
import time
import sqlalchemy.sql.default_comparator
reset = attr('reset')
red = fg('red')
orange = fg('208')
green = fg('green')
blue = fg('blue')

print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
print(blue + '''
                 _____                 _ _   _   _                _           
                | ____|_ __ ___   __ _(_) | | | | | ___  __ _  __| | ___ _ __ 
                |  _| | '_ ` _ \ / _` | | | | |_| |/ _ \/ _` |/ _` |/ _ \ '__|
                | |___| | | | | | (_| | | | |  _  |  __/ (_| | (_| |  __/ |   
                |_____|_| |_| |_|\__,_|_|_| |_| |_|\___|\__,_|\__,_|\___|_|   
                                                                      
            _                _           _       _____           _  __     ___   ___  
           / \   _ __   __ _| |_   _ ___(_)___  |_   _|__   ___ | | \ \   / / | / _ \ 
          / _ \ | '_ \ / _` | | | | / __| / __|   | |/ _ \ / _ \| |  \ \ / /| || | | |
         / ___ \| | | | (_| | | |_| \__ \ \__ \   | | (_) | (_) | |   \ V / | || |_| |
        /_/   \_\_| |_|\__,_|_|\__, |___/_|___/   |_|\___/ \___/|_|    \_/  |_(_)___/ 
                               |___/                                                                                                                                      
''' + reset)
print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')


def hlp():
    global choice
    print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print(blue + '''
     
         _   _      _                         _      _    _                 _   
        | | | | ___| |_ __     __ _ _ __   __| |    / \  | |__   ___  _   _| |_ 
        | |_| |/ _ \ | '_ \   / _` | '_ \ / _` |   / _ \ | '_ \ / _ \| | | | __|
        |  _  |  __/ | |_) | | (_| | | | | (_| |  / ___ \| |_) | (_) | |_| | |_ 
        |_| |_|\___|_| .__/   \__,_|_| |_|\__,_| /_/   \_\_.__/ \___/ \__,_|\__|
                     |_|  
                                                                                            
    ''' + reset)
    print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')



    print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _____ About _____ _____ _____ _____ _____ _____ _____ _____ __ ' + reset)
    print('''
This program performs Automated Email header analysis, analyzing SPF, DMKIM and DMARC authentication results found in 
the header section of emails. 
The program also checks if the email contains attachments. 
The program performs a risk assessment based on the results of the checks performed. 
The program also allows the user to log IP addresses flagged as high risk during the analysis process to
a MySql database.

The program allows the user to analyze one email at a time or multiple emails from a local directory.
The current version of the program is designed to work with Gmail emails only.

Author: Kevin O'Sullivan
    ''')
    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ ___ Analysing one email _____ _____ _____ _____ _____ _____ __ ' + reset)
    print('''
To Analyse one email navigate from the Menu system selecting the options you would like. 
You will be prompted to select a file.
Navigate to the location of the email file and select it. 
The analysis process will then be performed on the email.
    ''')
    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _ Analysing Multiple emails _____ _____ _____ _____ _____ _____ ' + reset)
    print('''
To Analyse multiple emails at once navigate from the Menu system selecting the options you would like. 
You will be prompted to select a Folder. 
Navigate to the folder containing the email files and select it. 
The analysis process will then be performed on the emails in the folder.
        ''')

    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _ __ _ Analysis Process _____ _____ _____ _____ _____ _____ ____ ' + reset)
    print('''
The Analysis process will perform the following checks on the email(s) selected:

Check if SPF checks passed
Check if DKIM checks passed
Check if DMARC checks passed
Check if the email contains attachments
Check the type of attachments contained in the email

The Analysis process will return the following information from the email(s) selected:

The receiving address
The sender address
Time and date the email was received
The return path
Associated Client IP address
Information relating to the risk assessment

Multiple SPF, DKIM or DMARC checks may be performed on an email on its travels. 
The analysis process will look at each one of the instances of each of the checks.
            ''')
    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _ _ Risk Assessment Process _____ _____ _____ _____ _____ _____ __ ' + reset)
    print('''
The risk assessment process will try to give an estimated level of risk based on the checks performed on the email.
The process will try to determine the likelihood of the email containing Malware as well as if the email may pose a 
threat of being a Malware-less- Phishing or Spear Phishing attempt. 
The Malware aspect will be determined based on if the email contains attachments or not.

The risk assessment process looks at the following:

If there were failed SPF checks
if there were failed DKIM checks
if there were failed DMARC checks
if the email contains attachments

If zero of the three checks performed doesn't have an instance of that check failing one or more times and the email 
does not contain attachments, the process will return:

Malware chance - LOW
Risk of Malware-less Phishing or Spear Phishing attempt - LOW

If zero of the three checks performed doesn't have an instance of that check failing one or more times and the email 
contains 1 or more attachments the process will return:

Malware chance - LOW
Risk of Malware-less Phishing or Spear Phishing attempt - LOW

If one of the three checks performed has an instance of that check failing one or more times and the email
does not contain attachments, the process will return:

Malware chance - LOW
Risk of Malware-less Phishing or Spear Phishing attempt - MEDIUM

If one of the three checks performed has an instance of that check failing one or more times,and the email 
contains 1 or more attachments the process will return:


Malware chance - MEDIUM
Risk of Malware-less Phishing or Spear Phishing attempt - MEDIUM


If two of the three checks performed has an instance of that check failing one or more times and the email 
does not contain attachments, the process will return:

Malware chance - LOW
Risk of Malware-less Phishing or Spear Phishing attempt - HIGH


If two of the three checks performed has an instance of that check failing one or more times and the email 
contains 1 or more attachments the process will return:

Malware chance - HIGH
Risk of Malware-less Phishing or Spear Phishing attempt - HIGH


If three of the three checks performed has an instance of that check failing one or more times and the email 
contains 1 or more attachments the process will return:

Malware chance - VERY HIGH
Risk of Malware-less Phishing or Spear Phishing attempt - VERY HIGH


If three of the three checks performed has an instance of that check failing one or more times and the email 
does not contain attachments, the process will return:

Malware chance - LOW
Risk of Malware-less Phishing or Spear Phishing attempt - VERY HIGH


The risk assessment process is intended to be used as a guide to help highlight emails that may be a risk.
                ''')

    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _ IP Blacklisting Option _____ _____ _____ _____ _____ _____ ' + reset)
    print('''
The program includes an option to blacklist the Associated Client IP addresses of the emails flagged as high risk during 
the analysis process.

IP addresses will be flagged if:

Either the Malware Chance or the Risk of Malware-less Phishing or Spear Phishiing is determined to be: HIGH or VERY HIGH

The Blacklisting option gives you the option to use an existing table or create a new table.

To use this option you will need to ensure the following:

You have MySql installed and running on the host you want to connect to
You have created a database (A new or Existing database can be used)
When choosing to use the existing table option, you are using a table created by this application or a table created
using the specification below:

Columns:
Id int AI PK 
Flagged_IP varchar(25) 
Sender_Address varchar(140) 
Receiving_Address varchar(140) 
Time_Received varchar(140)
            ''')

    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _ Future Developments _____ _____ _____ _____ _____ _____ ' + reset)
    print('''
Future versions of the program aim to include support for other email services. 

It is also planned to include functionality to enable the user to change the logging level they would like for the IP
blacklisting functionality. 

Other functionality may include extracting the subject line from each email and also creating a method for extracting
and analysing links contained in the body of the email.
                ''')
    print('')
    print(blue + '_____ _____ _____ _____ _____ _____ _ _ Acknowledgements _____ _____ _____ _____ _____ _____ __' + reset)
    print('''
This program was developed for a final year project in Bsc in IT Management, Cork Institute of Technology, Cork, Ireland.
The author would like to thank Byron Treacy and Tríona McSweeney for their guidance throughout the project.

                    ''')


    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _______ ')

    print('Please choose:')
    print('b. Go back to Main Menu')
    print('e. Exit')

    choice = input('Enter Choice(b or e): ')

def menu2():
    global bldb
    print('')
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print(blue + '_____ _____ _____ _____ _____ _____ ___Blacklist IP Menu _____ _____ _____ _____ _____ _____ __ ' + reset)
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print('')
    print('Would you like to append IP addresses flaged as high risk during the analysis process\nto a MySql database for blacklisting purposes?')

    print ('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print('Please choose:')
    print('y. Yes')
    print('n. No')
    print('b. Go back to Main Menu')
    print('e. Exit')
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')


    bldb =input('Enter choice (y or n or b or e): ')

def menu3():
    global table_choice
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print(blue + '_____ _____ _____ _____ _____ _____ ___ Table option Menu _____ _____ _____ _____ _____ ____ __ ' + reset)
    print('_____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print('Create new table or use an existing table?')
    print('')
    print(orange + 'NOTE: You will need to create a MySql database first and ensure the service is running on the host you specify below.' + reset)
    print('')
    print(orange + 'NOTE: Existing tables can only be used if they were created by this application on previous use\nor you can use a table created with the values specified in the help page.' + reset)
    print('')


    print('Please choose:')
    print('')
    print('1. Create new table')
    print('2. Use Existing table')
    print('3. Go back to Main Menu')
    print('4. Exit')
    print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    table_choice = input('''Create new table or use existing table?(1 or 2 or 3 or 4): ''')



def menu():
    print(blue + ' _____ _____ _____ _____ _____ _____ _____ Main Menu _____ _____ _____ _____ _____ _____ _____ _ ' + reset)
    print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')
    print(orange + 'NOTE: When selecting option 2 please ensure the directory chosen only contains email files.' + reset)
    print('')
    print('Please choose:')
    print('')
    print('1. Analyse one email')
    print('2. Analyse multiple emails')
    print('3. Help')
    print('4. Exit')
    print(' _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ ')


    ans = input('Enter here(1, 2 or 3 or 4): ')

    if ans == '1':
        menu2()

        if bldb == 'y' or bldb == 'Y':
            menu3()
            if table_choice == '1':
                FL2.createtbl()
                FL2.parse()
                FL2.spf()
                FL2.dkim()
                FL2.dmarc()
                FL2.attach()
                FL2.attachtype()
                FL2.clientip()
                FL2.risk()
                menu()
            if table_choice == '2':
                FL2.tbl_exists()
                FL2.parse()
                FL2.spf()
                FL2.dkim()
                FL2.dmarc()
                FL2.attach()
                FL2.attachtype()
                FL2.clientip()
                FL2.risk()
                menu()
            if table_choice == '3':
                menu()
            if table_choice == '4':
                exit()
            elif table_choice != '1' or table_choice != '2':
                print('Invalid Option, Please choose from the options below:')
                menu()

        if bldb == 'n' or bldb == 'N':
            FL2.parse()
            FL2.spf()
            FL2.dkim()
            FL2.dmarc()
            FL2.attach()
            FL2.attachtype()
            FL2.clientip()
            FL2.risk_no_bl()
            menu()
        if bldb == 'b' or bldb == 'B':
            menu()

        if bldb == 'e' or bldb == 'E':
            exit()
        else:
            print('Invalid Option, Please choose from the options below:')
            menu()


    if ans == '2':
        menu2()

        if bldb == 'y' or bldb == 'Y':
            menu3()
            if table_choice == '1':
                FL2.createtbl()
                FL2.parsemulti()
                menu()
            if table_choice == '2':
                FL2.tbl_exists()
                FL2.parsemulti()
                menu()
            if table_choice == '3':
                menu()
            if table_choice == '4':
                exit()
            else:
                print('Invalid Option, Please choose from the options below:')
                menu()

        if bldb == 'n' or bldb == 'N':
            FL2.parsemulti_no_bl()
            menu()
        if bldb == 'b' or bldb == 'B':
            menu()
        if bldb == 'e' or bldb == 'E':
            exit()
        else:
            print('Invalid Option, Please choose from the options below:')
            menu()

    if ans == '3':
        hlp()

        if choice == 'b' or choice == 'B':
            menu()

        if choice == 'e' or choice == 'E':
            exit()
        else:
            print('Invalid Option, Please choose from the options below')
            menu()

    if ans == '4':
        exit()

    else:
        print('Invalid Option, Please choose from the options below')
        menu()
menu()
