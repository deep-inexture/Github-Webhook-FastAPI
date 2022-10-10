import hashlib
import hmac
import http
import json
import os

from fastapi import FastAPI, Header, HTTPException, Request
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# 1-----------------------------------------------------------------------------------------------------------------
# def generate_hash_signature(
#     secret: bytes,
#     payload: str,
#     digest_method=hashlib.sha1,
# ):
#     return hmac.new(secret, payload, digest_method).hexdigest()
#
#
# @app.post("/webhook", status_code=http.HTTPStatus.ACCEPTED)
# async def webhook(request: Request, x_hub_signature: str = Header(None)):
#     payload = await request.body()
#     secret = os.environ.get("SECRET_KEY").encode("utf-8")
#     signature = generate_hash_signature(secret, payload)
#     if x_hub_signature != f"sha1={signature}":
#         raise HTTPException(status_code=401, detail="Authentication error.")
#     print(payload)
#     # print(json.dumps(payload))
#     return {payload}


# 2-------------------------------------------------------------------------------------------------
WEBHOOK_SECRET = os.getenv("SECRET_KEY")


# caclulate hmac digest of payload with shared secret token
def calc_signature(payload):
    digest = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"), msg=payload, digestmod="sha1"
    ).hexdigest()
    return f"sha1={digest}"


@app.post("/webhook")
async def webhook_handler(request: Request):
    # verify webhook signature
    raw = await request.body()
    signature = request.headers.get("X-Hub-Signature")
    if signature != calc_signature(raw):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # handle events
    payload = await request.json()
    event_type = request.headers.get("X-Github-Event")
    # return {'raw': raw, 'payload': payload, 'event_type':event_type}

    action = payload.get("action")
    if event_type == "create":

        return {'action': action, 'payload': payload}
    elif event_type == "delete":
        return {'action': action, 'payload': payload}
    else:
        return {'action': action, 'payload': payload}
    # reviews requested or removed
    # if event_type == "pull_request":
    #     action = payload.get("action")
    #     if action == "review_requested":
    #     # TODO: store review request
    #         return "ok"
    #     elif action == "review_request_removed":
    #         # TODO: delete review request
    #         return "ok"
    #     return "ok"
    #
    # # review submitted
    # if event_type == "pull_request_review" and payload.get("action") == "submitted":
    #     # TODO: update review request
    #     return "ok"
    #
    # # ignore other events
    # return "ok"
