import base64
import datetime
import hashlib
import math
import random
import re
import warnings
from typing import Any, Optional, cast
from urllib.parse import parse_qs, urlparse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as crypto_pad

from .auth_wrapper import WebLoginInterceptor
from .browser_mimic import BrowserMimic
from .errors import *
from .utils import *


class IAMPassword:
    MAX_SAFE_INTEGER = 9007199254740991

    @staticmethod
    def md5_hex(strn: str):
        return hashlib.md5(strn.encode()).hexdigest()

    @staticmethod
    def sha1_hex(strn: str):
        return hashlib.sha1(strn.encode()).hexdigest()

    AES_KEY = md5_hex(str(MAX_SAFE_INTEGER))
    AES_IV = sha1_hex(AES_KEY)

    @staticmethod
    def encrypt_aes(string: str) -> str:
        '''feilian uses AES/CBC/PKCS7/hex'''
        aes = AES.new(IAMPassword.AES_KEY.encode(), AES.MODE_CBC, IAMPassword.AES_IV.encode()[:16])
        encd_data = aes.encrypt(crypto_pad(string.encode(), AES.block_size, style='pkcs7'))
        return encd_data.hex()


class NKUIAM(BrowserMimic):
    user: str; password: str

    @classmethod
    def domain(cls) -> str: return 'iam.nankai.edu.cn'

    def __init__(self, user: str, password: str):
        self.user = user; self.password = password
        super().__init__()

    @staticmethod
    def grep_global_info(webpage: str):
        '''这里其实应该用BeautifulSoup和esprima找，但是我偷懒了'''
        GINFO_REGEX = r'window\.globalInfo = {(?P<content>[^{}]*)};'
        match = re.search(GINFO_REGEX, webpage)
        if match is None:
            raise ServerBrokePromiseError('无法从登录页中抓取globalInfo')
        result: dict[str, Any] = {}
        for kv in map(str.strip, match.group('content').split(',')):
            k, v = map(str.strip, kv.split(':'))
            result[k] = eval(v, {'true': True, 'false': False, 'null': None})
        return result

    def uncached_login(self, srv_url: str, resp_try: requests.Response) -> str:
        resp_gate = self.document(resp_try.headers['Location'], allow_redirects=False)
        global_info = self.grep_global_info(resp_gate.text)
        fe_version = cast(str, global_info['VERSION']).removeprefix('portal-fe-')
        api_misc_headers = {
            'csrf-token': self.cookies['csrf-token'],
            'X-Fe-Version': fe_version,
            'X-Version-Check': '0',
        }
        resp_login = self.xhr('POST', '/api/v1/login',
            params={'os': 'web'},
            headers=api_misc_headers,
            json={
                'login_scene': 'feilian',
                'account_type': 'userid',
                'account': self.user,
                'password': IAMPassword.encrypt_aes(self.password),
            },
            allow_redirects=False
        )
        try:
            login_info = resp_login.json()
            status = login_info['code']
            if status != 0:
                if status == 10110001: msg = '用户名或密码错误'
                else: msg = '未知错误'
                raise LoginProcedureError('/api/v1/login', msg)
            logincas_path = login_info['data']['next']['link']
        except LoginProcedureError: raise
        except Exception as err: raise ServerBrokePromiseError('意外错误') from err
        resp_logincas = self.xhr('GET', logincas_path, allow_redirects=False)
        return resp_logincas.headers['Location']

    def redirected_login(self, srv_url: str, resp_try: requests.Response) -> str:
        return resp_try.headers['Location']

    def login(self, req_url: str, srv_url: str) -> str:
        if self.user_agent is None:
            warnings.warn('未设置User-Agent', category=YouMayBeNoticedWarning)
        resp_try = self.document('/api/cas/login', params={'service': srv_url}, allow_redirects=False)
        if resp_try.is_redirect:
            new_loc = urlparse(resp_try.headers['Location'])
            if new_loc.netloc == '':
                ticket_link = self.uncached_login(srv_url, resp_try)
            else:
                ticket_link = self.redirected_login(srv_url, resp_try)
        else:
            raise ServerBrokePromiseError(f'未知请求状态({resp_try.status_code})')
        return ticket_link

    def should_handle(self, resp: requests.Response):
        # 检查是否进入SSO
        if not resp.is_redirect: return None
        new_loc = resp.headers['Location']
        parsed_new_loc = urlparse(new_loc)
        if not parsed_new_loc.netloc == self.domain(): return None
        if not parsed_new_loc.path == '/api/cas/login': return None
        # 检验链接完整性
        queries_new_loc = parse_qs(parsed_new_loc.query)
        try: srv_url = get_from_queries(queries_new_loc, 'service')
        except ValueError as exc:
            raise ServerBrokePromiseError(f'重定向({new_loc})中service参数异常') from exc
        req = resp.request; assert req.url is not None
        if not url_is_similar(urlparse(req.url), urlparse(srv_url)):
            raise ServerBrokePromiseError(f'重定向({new_loc})指向的不是原请求网址({req.url})')
        return srv_url


class NKUIAMAuth(WebLoginInterceptor):
    def __init__(self, user: str, password: str):
        super().__init__(NKUIAM(user, password))
