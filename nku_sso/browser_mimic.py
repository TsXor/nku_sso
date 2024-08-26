from typing import Optional
from abc import ABC, abstractmethod
import requests


HeadersT = dict[str, str]


BROWSER_BASE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

BROWSER_DOCUMENT_HEADERS = {
    **BROWSER_BASE_HEADERS,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-User': '?1',
}

BROWSER_XHR_HEADERS = {
    **BROWSER_BASE_HEADERS,
    'Accept': '*/*',
    'X-Requested-With': 'XMLHttpRequest',
    'Sec-Fetch-Dest': 'script',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'same-origin',
}


class BrowserMimic(ABC):
    sess: requests.Session

    @classmethod
    @abstractmethod
    def domain(cls) -> str: ...

    @classmethod
    def address(cls): return 'https://' + cls.domain()

    @classmethod
    def url(cls, path: str): return cls.address() + path

    def __init__(self):
        self.sess = requests.Session()
        self.sess.headers = {
            'Host': self.domain(),
            'Origin': self.address(),
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

    @property
    def cookies(self): return self.sess.cookies

    def document(self, path: str, headers: HeadersT | None = None, **kwargs):
        final_headers = BROWSER_DOCUMENT_HEADERS.copy()
        if headers: final_headers.update(headers)
        return self.sess.get(self.url(path), headers=final_headers, **kwargs)

    def xhr(self, method: str, path: str, headers: HeadersT | None = None, **kwargs):
        final_headers = BROWSER_XHR_HEADERS.copy()
        if headers: final_headers.update(headers)
        return self.sess.request(method, self.url(path), headers=final_headers, **kwargs)
