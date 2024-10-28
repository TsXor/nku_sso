class YouMayBeNoticedWarning(UserWarning):
    '''此类警告表示你当前的行为有被服务端发现非人的可能'''
    pass

class ServerBrokePromiseError(Exception):
    '''此类异常表示依赖的某些服务端行为发生了改变'''
    pass

class LoginProcedureError(Exception):
    '''此类异常表示登录过程中发生了确定的异常'''
    stage: str
    def __init__(self, stage: str, *args):
        self.stage = stage
        super().__init__(*args)
