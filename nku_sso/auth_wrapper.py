from typing import Optional, Protocol
import requests
from requests.auth import AuthBase as RequestsAuthBase


class WebLoginImpl(Protocol):
    def should_handle(self, resp: requests.Response) -> Optional[str]: ...
    def login(self, req_url: str, srv_url: str) -> str: ...

class WebLoginInterceptor(RequestsAuthBase):
    impl: WebLoginImpl

    def __init__(self, impl: WebLoginImpl):
        self.impl = impl

    def login_if_needed(self, resp: requests.Response, **kwargs):
        srv_url = self.impl.should_handle(resp)
        if srv_url is None: return resp
        req = resp.request; assert req.url is not None
        req.url = self.impl.login(req.url, srv_url)
        return resp.connection.send(req, **kwargs)

    def __call__(self, req: requests.PreparedRequest):
        assert req.url is not None
        req.register_hook("response", self.login_if_needed)
        return req
