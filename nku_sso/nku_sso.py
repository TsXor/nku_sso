from typing import Optional, Any, cast
import math, datetime, re, random, hashlib, base64, warnings
from Crypto.Cipher import PKCS1_v1_5 as CryptoPKCS1
from Crypto.PublicKey import RSA as CryptoRSA
from urllib.parse import urlparse, parse_qs
import requests
from .utils import *
from .errors import *


class SSOPassword:
    PUBKEY =    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfy7Co/zbDUe" \
                "gHFoAxuEzAyllnf6dxt50iipCVVns8Vzx6BCJmYEYa6/OlLrhJ" \
                "SB7yW4igfyotKkwsd8lA1d3nP6HWb7s4t2HWTKo/Tcb/LVzUGX" \
                "9Juz8ifF1tHduAAubJNVlArr21uu1atk9y4K6Um3MKwWw5tQ/b" \
                "MP4NdYMaRQIDAQAB"
    PUBKEY_DECODED = CryptoRSA.import_key(base64.b64decode(PUBKEY))

    @staticmethod
    def md5(strn: str):
        return hashlib.md5(strn.encode()).hexdigest()

    @staticmethod
    def rsa(text: str):
        cipher = CryptoPKCS1.new(SSOPassword.PUBKEY_DECODED)
        enc_bin = cipher.encrypt(text.encode())
        return base64.b64encode(enc_bin).decode()


class NKUSSO:
    DOMAIN = 'sso.nankai.edu.cn'
    ADDRESS = 'https://' + DOMAIN

    sess: requests.Session
    user: str; password: str

    @staticmethod
    def grep_lt(webpage: str):
        '''
        lt是请求的一个重要参数，它是通过某种模板引擎注入网页脚本的。
        在这里用正则表达式从网页中抓取lt的值。
        Man, what can I say. PHP is the best language.
        '''
        LT_REGEX = r'var _lt = "(?P<content>.*)";'
        result = re.search(LT_REGEX, webpage)
        if result is None:
            raise ServerBrokePromiseError('无法从登录页中抓取lt')
        return result.group('content')

    @staticmethod
    def load_code_headers():
        '''生成loadcode方法用到的特殊请求头。'''
        now_time = datetime.datetime.now()
        timestamp = now_time.year * int(now_time.timestamp() * 1000) * 33
        randnum = math.floor(random.random() * 1000)
        auth_str = str(timestamp) + str(randnum)
        return { "Authorization": auth_str, }



    @staticmethod
    def url(path: str): return NKUSSO.ADDRESS + path

    def __init__(self, user: str, password: str):
        self.sess = requests.Session()
        self.user = user; self.password = password
        self.sess.headers = {
            'Host': self.DOMAIN,
            'Origin': self.ADDRESS,
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'X-Requested-With': 'XMLHttpRequest',
        }

    @property
    def user_agent(self) -> Optional[str]:
        if 'User-Agent' in self.sess.headers:
            return str(self.sess.headers['User-Agent'])
        else:
            return None

    @user_agent.setter
    def user_agent(self, new_ua: Optional[str]):
        if new_ua is None:
            del self.sess.headers['User-Agent']
        else:
            self.sess.headers['User-Agent'] = new_ua

    def uncached_login(self, srv_url: str, resp_login: requests.Response) -> str:
        var_lt: str = self.grep_lt(resp_login.text)
        
        resp_load_code = self.sess.post(self.url('/sso/loadcode'), headers=self.load_code_headers())
        try: var_rand: str = resp_load_code.json()['rand']
        except Exception as err: raise ServerBrokePromiseError('意外错误') from err
        
        passwd_md5 = SSOPassword.md5(self.password)
        passwd_rsa = SSOPassword.rsa(self.password)
        
        resp_check_role = self.sess.post(self.url('/sso/checkRole'), data={
            'username': self.user,
            'password': passwd_md5,
            't': passwd_rsa,
            'rand': var_rand,
            'service': srv_url,
            'loginType': '0',
        })
        try:
            content_check_role: dict[str, Any] = resp_check_role.json()
            if content_check_role.get('haserror'):
                raise LoginProcedureError('/sso/checkRole', content_check_role.get('message'))
        except LoginProcedureError: raise
        except Exception as err: raise ServerBrokePromiseError('意外错误') from err
        
        resp_check_weak = self.sess.post(self.url('/sso/checkWeak'), data={
            'username': self.user,
            'password': passwd_md5,
        })
        try:
            content_check_weak: dict[str, Any] = resp_check_weak.json()
            if content_check_weak.get('code') == 500:
                raise LoginProcedureError('/sso/checkWeak', '未知错误')
            if content_check_weak.get('code') == 505:
                raise LoginProcedureError('/sso/checkWeak', '密码太弱，需要修改')
            if content_check_weak.get('code') == 506:
                raise LoginProcedureError('/sso/checkWeak', '密码错误，需要找回')
        except LoginProcedureError: raise
        except Exception as err: raise ServerBrokePromiseError('意外错误') from err
        
        resp_login = self.sess.post(self.url('/sso/login'), data={
            'ajax': '1',
            'username': self.user,
            'password': passwd_md5,
            'lt': var_lt,
            'rand': var_rand,
            't': passwd_rsa,
            'roleType': '',
            'service': srv_url,
            'loginType': '0',
        })
        try:
            content_login: dict[str, Any] = resp_login.json()
            if content_login.get('status') != True:
                raise LoginProcedureError('/sso/login', '未知错误')
            if content_login.get('message') == 'FIRST_LOGIN':
                raise LoginProcedureError('/sso/login', '首次登录，需要更新密码')
            return content_login['message']
        except LoginProcedureError: raise
        except Exception as err: raise ServerBrokePromiseError('意外错误') from err

    def redirected_login(self, srv_url: str, resp_login: requests.Response) -> str:
        ticket_url = resp_login.headers['Location']
        parsed_ticket_url = urlparse(ticket_url)
        parsed_srv_url = urlparse(srv_url)
        if not url_is_similar(parsed_srv_url, parsed_ticket_url):
            raise ServerBrokePromiseError(f'重定向({ticket_url})指向的不是原服务网址({srv_url})')
        queries_ticket_url = parse_qs(parsed_ticket_url.query)
        try: return get_from_queries(queries_ticket_url, 'ticket')
        except ValueError as exc:
            raise ServerBrokePromiseError(f'重定向({ticket_url})中ticket参数异常') from exc

    def login(self, srv_url: str) -> str:
        if self.user_agent is None:
            warnings.warn('未设置User-Agent', category=YouMayBeNoticedWarning)
        resp_try = self.sess.get(self.url('/sso/login'), params={'service': srv_url}, allow_redirects=False)
        if resp_try.status_code == 200:
            return self.uncached_login(srv_url, resp_try)
        elif resp_try.is_redirect:
            return self.redirected_login(srv_url, resp_try)
        else:
            raise ServerBrokePromiseError(f'未知请求状态({resp_try.status_code})')
