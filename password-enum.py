import argparse
from ast import arg

from distutils.log import error

parser = argparse.ArgumentParser("password_enum")

parser.add_argument(
    "--type", help="The method of injection to use.", choices=['error', 'dom', 'delay'], default='error')
parser.add_argument(
    "--success", help="A string to search for in the response that denotes successful execution.", type=str, default="Internal Server Error")
parser.add_argument(
    "--template", help="The request template used to contain the injection code.", type=str, default='template.txt')
parser.add_argument(
    "url", help="The target URL.", type=str)
parser.add_argument(
    "table_name", help="The table containing the information to enumerate.", type=str)
parser.add_argument(
    "entry_identifer", help="The identifer used to match a record to enumerate.", type=str)
parser.add_argument(
    "field_name", help="The field to enumerate.", type=str)
parser.add_argument(
    "--wordlist", help="The wordlist used for payloads", type=str, default="wordlists/atob0to9.txt"
)

# Settings
MARKER = '[[INJECTION_POINT]]'
FIELD_LENGTH_LIMIT = 50

# SQL Commands
BASIC_CMD = "||(SELECT '')||"
ORACLE = {
    BASIC_CMD: "||(SELECT '' from dual}||"
}

ORACLE.BASIC_CMD

args = parser.parse_args()
tableName = args.table
identifier = args.identifier
target = args.field

try:
    wlFile = open(args.wordlist, "r")
except FileNotFoundError:
    error("Wordlist does not exists!")
else:
    values = wlFile.read()
    payloadValues = values.split(',')
    wlFile.close()

try:
    templateFile = open(args.template, "r")
except FileNotFoundError:
    error("Template does not exists!")
else:
    template = templateFile.read()
    templateFile.close()


def checkSqlCompatible(tableName):
    print("Checking SQL is being used")


def checkTableExists(tableName):
    print("Checking table exists")


def checkColumnExists(tableName, columnExists):
    print("Checking table exists")


def enumerateFieldLength(tableName, columnExists):
    print("Getting field length...")
    for x in FIELD_LENGTH_LIMIT:
        print("Checking length ", x)


def generateSqlStatement(sql):
    print("Generating SQL statement")


def executeRequest(payload):
    print("Sending payload")
    #request = requests.get(args.url, headers={})


checkTableExists(tableName)
checkColumnExists(tableName, identifier)
