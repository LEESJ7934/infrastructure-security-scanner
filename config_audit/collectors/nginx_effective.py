"""Bounded read-only parser for explicit nginx HTTP settings.

Supports http/server/literal prefix locations and caller-supplied exact Include
files, with inheritance. Does not execute nginx or read paths. Regex/named
locations, conditional/dynamic control and unresolved includes require review.
Caller must still validate nginx -t, inventory completeness and actual HTTP.
"""
import shlex

KEYS = ("autoindex_disabled", "tokens_hidden", "private_blocked", "access_logging")
NEUTRAL = frozenset({"worker_processes", "pid", "error_log", "worker_connections", "listen",
    "server_name", "root", "alias", "proxy_pass", "client_body_temp_path", "proxy_temp_path",
    "fastcgi_temp_path", "uwsgi_temp_path", "scgi_temp_path", "log_format", "default_type",
    "sendfile", "keepalive_timeout", "charset", "index", "client_max_body_size"})
CONTROLS = frozenset({"autoindex", "server_tokens", "access_log", "return", "deny"})


class UnsupportedConfig(ValueError):
    pass


def effective_values(raw, *, includes=None):
    unknown = dict.fromkeys(KEYS)
    sources = includes or {}
    try:
        if not isinstance(raw, str) or len(raw.encode()) > 131072 or not isinstance(sources, dict):
            raise UnsupportedConfig("config_size_or_type")
        budget = [0, 0]
        def tokens(text):
            lexer = shlex.shlex(text, posix=True, punctuation_chars="{};")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            result = []
            for token in lexer:
                result.extend(list(token) if token and all(x in "{};" for x in token) else [token])
            return result
        def parse(text, stack=()):
            budget[0] += len(text.encode()); budget[1] += 1
            if budget[0] > 262144 or budget[1] > 32 or len(stack) > 8:
                raise UnsupportedConfig("include_budget")
            stream = iter(tokens(text))
            def block(nested=False, depth=0):
                if depth > 16: raise UnsupportedConfig("context_depth")
                rows = []; words = []
                for token in stream:
                    if token == "}":
                        if words or not nested: raise UnsupportedConfig("unbalanced_context")
                        return rows
                    if token == "{":
                        if not words: raise UnsupportedConfig("empty_context")
                        rows.append((tuple(words), block(True, depth+1))); words=[]
                    elif token == ";":
                        if not words: raise UnsupportedConfig("empty_directive")
                        if words[0] == "include":
                            if len(words)!=2 or words[1] in stack or words[1] not in sources:
                                raise UnsupportedConfig("include_unresolved_or_cycle")
                            value=sources[words[1]]
                            if not isinstance(value,str):raise UnsupportedConfig("include_type")
                            rows.extend(parse(value, stack+(words[1],)))
                        else: rows.append((tuple(words), None))
                        words=[]
                    else: words.append(token)
                if nested or words: raise UnsupportedConfig("incomplete_context")
                return rows
            return block()
        tree = parse(raw)
        def inspect(rows, context):
            controls={};children=[]
            for words,body in rows:
                name=words[0]
                if body is not None:
                    valid=(context=='main' and name in ('events','http') and len(words)==1
                           or context=='http' and words==('server',)
                           or context in ('server','location') and name=='location' and len(words)==2
                           and words[1].startswith('/') and not any(c in words[1] for c in '$*?'))
                    if not valid:raise UnsupportedConfig("unsupported_context")
                    children.append((words,body))
                elif name in CONTROLS:
                    if name in controls:raise UnsupportedConfig("duplicate_control")
                    if any('$' in v for v in words[1:]):raise UnsupportedConfig("dynamic_control")
                    controls[name]=words[1:]
                elif name not in NEUTRAL:raise UnsupportedConfig("unsupported_directive")
            return controls,children
        main,children=inspect(tree,'main')
        http=[body for words,body in children if words==('http',)]
        if len(http)!=1:raise UnsupportedConfig('one_http_context_required')
        # Inspect events too, so unrecognized input never silently disappears.
        for words,body in children:
            if words==('events',):inspect(body,'events')
        hc,servers=inspect(http[0],'http')
        if not servers:raise UnsupportedConfig('server_inventory_empty')
        values=[]
        def onoff(v):return True if v==('off',) else False if v==('on',) else None
        def logging(v):return None if v is None else False if v==('off',) else True if len(v)>=1 and v[0] else None
        for words,body in servers:
            sc,locations=inspect(body,'server');base=dict(hc,**sc)
            contexts=[base];paths={}
            def walk(rows,parent,prefix=''):
                for words,body in rows:
                    path=words[1]
                    if path in paths:raise UnsupportedConfig('duplicate_location')
                    if prefix and not path.startswith(prefix):raise UnsupportedConfig('nested_location_scope')
                    lc,nested=inspect(body,'location');current=dict(parent,**lc)
                    paths[path]=current;contexts.append(current);walk(nested,current,path)
            walk(locations,base)
            def pathvalue(path,key):
                matches=[p for p in paths if path.startswith(p)]
                return paths[max(matches,key=len)].get(key) if matches else base.get(key)
            listing=onoff(pathvalue('/files/','autoindex'))
            tokenstates=[onoff(c.get('server_tokens')) for c in contexts]
            logstates=[logging(c.get('access_log')) for c in contexts]
            privreturn=pathvalue('/private/','return');privdeny=pathvalue('/private/','deny')
            # Rewrite return executes before access deny; deny all cannot make
            # an earlier return 200/redirect into blocked private content.
            private=(privreturn[0] in ('403','404') if privreturn else
                     True if privdeny==('all',) else False if '/private/' in paths else None)
            values.append(dict(autoindex_disabled=listing,
                tokens_hidden=False if False in tokenstates else None if None in tokenstates else True,
                access_logging=False if False in logstates else None if None in logstates else True,
                private_blocked=private))
        return {k:False if any(v[k] is False for v in values) else None if any(v[k] is None for v in values) else True for k in KEYS}
    except (UnsupportedConfig, ValueError, TypeError, UnicodeError):
        return unknown
