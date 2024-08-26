# NKU-SSO
今天来点学校运维不太想看的东西。

## 简单文档
- `NKUSSO`：SSO认证实现，暂时仅支持账号密码登录  
  构造：`NKUSSO(user: str, password: str)`  
  可用方法：  
  - `def login(srv_url: str) -> str: ...`  
    输入服务URL，返回ticket
- `NKUSSOAuth`：可在`requests`中使用的扩展认证。  
  构造：`NKUSSOAuth(user: str, password: str)`  
  使用例：
  ```python
  resp = requests.get('http://tycgs.nankai.edu.cn/User/LoginCas', auth=NKUSSOAuth(sso))
  ```
  注：这个扩展认证只有在访问的网址会跳转到SSO登录页时才会生效。    

## 使用例
```python
# 建议加上这一行以避免证书问题
import pip_system_certs.wrapt_requests
import requests
from nku_sso import NKUSSO, NKUSSOAuth

# 请填入自己的账号密码
sso = NKUSSO('...', '...')
# 请酌情使用合理的User-Agent
sso.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0'
with requests.Session() as sess:
    # 这样没有用，并不会触发SSO认证，因为这个网址不会直接跳转到SSO登录页，会停在一个确认页
    #resp = sess.get('http://tycgs.nankai.edu.cn/Views/User/User.html', auth=NKUSSOAuth(sso))
    # 这个网址会触发SSO登录，并使用返回的ticket登录网站
    resp = sess.get('http://tycgs.nankai.edu.cn/User/LoginCas', auth=NKUSSOAuth(sso))
    print(sess.cookies)
```

## 构建与安装
构建：
```bash
py -m pip install build
py -m build
```
安装：使用`pip`安装`dist`目录下生成的`.whl`文件。

## 这是什么玩意我看不懂
你无敌了孩子，找能看懂的给你讲。
