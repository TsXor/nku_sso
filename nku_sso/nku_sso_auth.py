import functools
from urllib.parse import urlparse, parse_qs
import requests
from requests.auth import AuthBase as RequestsAuthBase
from .nku_sso import NKUSSO
from .utils import *
from .errors import *


class NKUSSOAuth(RequestsAuthBase):
    sso: NKUSSO

    def __init__(self, sso: NKUSSO):
        self.sso = sso

    def login_if_needed(self, req: requests.PreparedRequest, resp: requests.Response, **kwargs):
        if not resp.is_redirect: return resp
        new_loc = resp.headers['Location']
        parsed_new_loc = urlparse(new_loc)
        if parsed_new_loc.netloc != self.sso.DOMAIN: return resp
        if parsed_new_loc.path != '/sso/login': return resp
        queries_new_loc = parse_qs(parsed_new_loc.query)
        try: svc_url = get_from_queries(queries_new_loc, 'service')
        except ValueError as exc:
            raise ServerBrokePromiseError(f'重定向({new_loc})中service参数异常') from exc
        assert req.url is not None
        parsed_req_url = urlparse(req.url)
        parsed_svc_url = urlparse(svc_url)
        if not url_is_similar(parsed_req_url, parsed_svc_url):
            raise ServerBrokePromiseError(f'重定向({new_loc})指向的不是原请求网址({req.url})')
        ticket = self.sso.login(req.url)
        req.url = parsed_req_url._replace(query=f'ticket={ticket}').geturl()
        with requests.Session() as tmp_sess:
            # 在临时会话内不带钩子地发送加了ticket的请求
            req_orig_hooks = req.hooks; req.hooks = {}
            real_resp = tmp_sess.send(req, allow_redirects=False, **kwargs)
            req.hooks = req_orig_hooks
        return real_resp

    def __call__(self, req: requests.PreparedRequest):
        assert req.url is not None
        resp_hook = functools.partial(self.login_if_needed, req)
        req.register_hook("response", resp_hook)
        return req
