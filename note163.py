import os
import requests
import sys
import json
import time
import datetime
import hmac
import hashlib
import base64
from urllib.parse import quote_plus
import requests
import urllib3

urllib3.disable_warnings()


# note.youdao.com 有道云笔记签到

user = ""
passwd = ""

secret = os.environ["SECRET"]
webhook = os.environ["WEBHOOK"]

if(user=="",passwd==""):
    user = input("账号:")
    passwd = input("密码:")

    
def noteyoudao(YNOTE_SESS: str, user: str, passwd: str):
    s = requests.Session()
    checkin_url = 'http://note.youdao.com/yws/mapi/user?method=checkin'
    cookies = {
        'YNOTE_LOGIN': 'true',
        'YNOTE_SESS': YNOTE_SESS
    }
    r = s.post(url=checkin_url, cookies=cookies, )
    if r.status_code == 200:
        # print(r.text)
        info = json.loads(r.text)
        total = info['total'] / 1048576
        space = info['space'] / 1048576
        t = time.strftime('%Y-%m-%d %H:%M:%S',
                          time.localtime(info['time'] / 1000))
        print(user+'签到成功，本次获取'+str(space) +
              'M, 总共获取' + str(total) + 'M, 签到时间' + str(t))
        dingtalk(user+'签到成功，本次获取'+str(space) +
              'M, 总共获取' + str(total) + 'M, 签到时间' + str(t))
    # cookie 登录失效，改用用户名密码登录
    else:
        login_url = 'https://note.youdao.com/login/acc/urs/verify/check?app=web&product=YNOTE&tp=ursto' \
                    'ken&cf=6&fr=1&systemName=&deviceType=&ru=https%3A%2F%2Fnote.youdao.com%2FsignIn%2F%2Flo' \
                    'ginCallback.html&er=https%3A%2F%2Fnote.youdao.com%2FsignIn%2F%2FloginCallback.html&vc' \
                    'ode=&systemName=Windows&deviceType=WindowsPC&timestamp=1517235699501'
        parame = {
            'username': user,
            'password': passwd
        }

        r = s.post(url=login_url, data=parame, verify=False)
        x = [i.value for i in s.cookies if i.name == 'YNOTE_SESS']
        if x.__len__() == 0:
            YNOTE_SESS = "-1"
            print(user+"登录失败")
            print(r.history)
            print(s.cookies)
            return
        else:
            print(user+'登陆成功，更新YNOTE_SESS,重新签到')
            YNOTE_SESS = x[0]
            noteyoudao(YNOTE_SESS, user, passwd)
            return YNOTE_SESS

def dingtalk(notification: str):
    timestamp = round(time.time() * 1000)
    secret_enc = bytes(secret, encoding='utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = bytes(string_to_sign, encoding='utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = quote_plus(base64.b64encode(hmac_code))
    #test
    #url="webhook"+str(timestamp)+"&sign="+sign
    #hk
    url=webhook+"&timestamp="+str(timestamp)+"&sign="+sign
    From_data = {
        "msgtype": "markdown",
        "markdown": {
            "title":"通知",
            "text": "#### 通知\n" +
            notification
        },
        "at": {
            "atMobiles": [
                ""
            ],
            "isAtAll": "false"
        }
    }
    response = requests.post(url, json=From_data)
    # 将Json格式字符串转字典
    content = json.loads(response.text)
    print(content)

if __name__ == "__main__":
    noteyoudao("", user, passwd)
