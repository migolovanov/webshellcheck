import re
import sys
import json
import random
import hashlib
import asyncio
import aiohttp
import argparse
from base64 import b64encode
from string import ascii_letters, digits
from urllib.parse import urlparse,quote_plus

def pprint(text,color=None):
    text=str(text)
    if color == "red":
        print("".join(["\033[31m", text, "\033[m"]))
    elif color == "green":
        print("".join(["\033[32m", text, "\033[m"]))
    elif color == "blue":
        print("".join(["\033[34m", text, "\033[m"]))
    elif color == "yellow":
        print("".join(["\033[93m", text, "\033[m"]))
    else:
        print(text)

def parse_cli_args():
    parser=argparse.ArgumentParser(description="Web-shell scanner")
    parser.add_argument("--url", "-u",
    	dest="url",
        required=True,
        help="URL of host for scanning,(e.g. http://testapp.com)")
    parser.add_argument("--file", "-f",
    	dest="file",
        default="shells.json",
        help="File with shells info in JSON format")
    parser.add_argument("--rate", "-r",
    	dest="rate",
        default=1000,
        help="HTTP-requests rate limit")
    parser.add_argument("--timeout",
    	dest="timeout",
        default=300,
        help="Allowed timeout for HTTP-requests")
    parser.add_argument("--keepalive",
    	dest="keepalive",
        default=180,
        help="Keepalive timeout for session")
    args=parser.parse_args()
    parsed_url=urlparse(args.url)
    url={"scheme":None,"host":None,"path":None}
    if not parsed_url.netloc:
        splitted=parsed_url.path.split("/")
        url["host"]=splitted[0]
        url["path"]="/{}".format("/".join(splitted[1:]))
    else:
        url["host"]=parsed_url.netloc
    url["path"]=url["path"] or "/"
    url["path"]=re.sub("[\s\/]*$","/",url["path"])
    url["scheme"]=url["scheme"] or "http"
    args.url="{scheme}://{host}{path}".format_map(url)
    return args

async def get_url(session,method,url,body,pattern,timeout=300):
    status=False
    try:
        async with getattr(session,method.lower())(url,data=body,allow_redirects=True,timeout=timeout) as resp:
            body=await resp.text()
            if re.search(pattern,body):
                status=True
    except Exception as err:
        pprint("[ERROR] {}".format(err),color="blue")
    return url, status


async def asynchronous(loop):
    args=parse_cli_args()
    data=json.loads(open(args.file,"rb").read())
    tasks=[]
    pprint("[INFO] Star scanning {}".format(args.url),color="blue")
    conn = aiohttp.TCPConnector(keepalive_timeout=args.keepalive, limit=args.rate)
    async with aiohttp.ClientSession(connector=conn,loop=loop) as session:
        payload=dict(pattern=''.join(random.choice(ascii_letters+digits) for i in range(10)))
        payload["payload"]="die(@md5({}));".format(payload["pattern"])
        payload["md5"]=hashlib.md5(payload["pattern"].encode("utf8")).hexdigest()
        for i,j in data.items():
            i=re.sub("^\/*","",i)
            for v in j:
                method="POST"
                body={}
                if "get" in v and ("post" not in v or not v["post"]):
                    method="GET"
                payload_to_replace=payload["payload"]
                if "encoding" in v and v["encoding"]=="base64":
                    payload_to_replace=b64encode(payload["payload"].encode("utf8")).decode("utf8")
                url="{}{}".format(args.url,i.format(payload=payload_to_replace))
                if "get" in v:
                    params=[]
                    for x,y in v["get"].items():
                        y=y.format(payload=payload_to_replace)
                        params.append("{}={}".format(x,quote_plus(y)))
                    url="{}?{}".format(url,"&".join(params))
                if "post" in v:
                    params=[]
                    for x,y in v["post"].items():
                        body[x]=y.format(payload=payload_to_replace)
                tasks.append(get_url(session,method,url,body,payload["md5"]))
            
        for task in asyncio.as_completed(tasks):
            url,status = await task
            if status:
                pprint("[SUCCESS] Web-shell found on {}".format(url),"red")
    pprint("[INFO] Done scanning {}".format(args.url),color="blue")

loop = asyncio.get_event_loop()
future = asyncio.ensure_future(asynchronous(loop))
loop.run_until_complete(future)
loop.close()
