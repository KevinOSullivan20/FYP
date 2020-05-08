
##Final Year Project - Automating Detection and Management of Malicious Email

### Author and Contributor List
-------------
Kevin O'Sullivan

### About

This program performs Automated Email header analysis, analyzing SPF, DMKIM and DMARC authentication results found in
the header section of emails.
The program also checks if the email contains attachments.
The program performs a risk assessment based on the results of the checks performed.
The program also allows the user to log IP addresses flagged as high risk during the analysis process to
a MySql database.

The program allows the user to analyze one email at a time or multiple emails from a local directory.
The current version of the program is designed to work with Gmail emails only.


### Installation instructions
-------------
```
git clone https://github.com/KevinOSullivan20/FYP/
```

#### After cloning install the reqirements:

```
pip install -r requirements.txt
```

### Running the program

```
python3 main.py
```

### How to use the program

_____ _____ _____ _____ _____ _____ ___ Analysing one email _____ _____ _____ _____ _____ _____ __


To Analyse one email navigate from the Menu system selecting the options you would like.
You will be prompted to select a file.
Navigate to the location of the email file and select it.
The analysis process will then be performed on the email.


_____ _____ _____ _____ _____ _____ _ Analysing Multiple emails _____ _____ _____ _____ _____ _____


To Analyse multiple emails at once navigate from the Menu system selecting the options you would like.
You will be prompted to select a Folder.
Navigate to the folder containing the email files and select it.
The analysis process will then be performed on the emails in the folder.


_____ _____ _____ _____ _____ _____ _ __ _ Analysis Process _____ _____ _____ _____ _____ _____ ____


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


_____ _____ _____ _____ _____ _____ _ _ Risk Assessment Process _____ _____ _____ _____ _____ _____ __


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


_____ _____ _____ _____ _____ _____ _ IP Blacklisting Option _____ _____ _____ _____ _____ _____

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


_____ _____ _____ _____ _____ _____ _ Future Developments _____ _____ _____ _____ _____ _____


Future versions of the program aim to include support for other email services.

It is also planned to include functionality to enable the user to change the logging level they would like for the IP
blacklisting functionality.

Other functionality may include extracting the subject line from each email and also creating a method for extracting
and analysing links contained in the body of the email.


_____ _____ _____ _____ _____ _____ _ _ Acknowledgements _____ _____ _____ _____ _____ _____ __


This program was developed for a final year project in Bsc in IT Management, Cork Institute of Technology, Cork, Ireland.
The author would like to thank Byron Treacy and Tríona McSweeney for their guidance throughout the project.
