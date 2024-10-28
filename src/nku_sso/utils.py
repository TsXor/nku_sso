from urllib.parse import ParseResult as UrlParseResult

def url_is_similar(a: UrlParseResult, b: UrlParseResult):
    return a.netloc == b.netloc and a.path == b.path

def get_from_queries(queries: dict[str, list[str]], key: str):
    if key not in queries: raise ValueError(f'参数中没有{key}')
    val_list = queries[key]
    if len(val_list) != 1: raise ValueError(f'参数中有多个{key}')
    return val_list[0]
