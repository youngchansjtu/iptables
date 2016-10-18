# -*- coding: utf8 -*-

import datetime
import json
import requests


def to_date(timestamp):
    date = datetime.datetime.fromtimestamp(timestamp)
    return date.strftime('%Y/%m/%d %H:%M:%S')


def to_str(bytes, encoding='utf8'):
    if isinstance(bytes, unicode):
        return bytes.encode(encoding).strip()
    return str(bytes).strip()


def to_unicode(string, decoding='utf8'):
    if isinstance(string, str):
        return string.decode(decoding)
    return unicode(string)


def send_pushover(message, priority):
    user = 'uqpdfd7ddidhsfy9eh2zb61qra4s38'
    token = 'av4hrt61558mbq57x8npg8mbekh6gv'
    header = {'Content-type': 'application/x-www-form-urlencoded'}
    data = {
        'user': user,
        'token': token,
        'message': message,
        'priority': priority
    }
    url = 'https://api.pushover.net/1/messages.json'
    req = requests.post(url, data, headers=header)
    req.close()
    return req.status_code


def read_cfg(jsonFile):
    try:
        with open(jsonFile) as fp:
            cfg = json.load(fp)
    except ValueError as e:
        print('Error: {msg}'.format(msg=e.msg))
        exit(1)
    except IOError as e:
        print('Error: {msg}'.format(msg=e.args[1]))
        exit(2)
    return cfg
