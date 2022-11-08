import requests
import hmac
import os

from fastapi import FastAPI, HTTPException, Request
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

WEBHOOK_SECRET = os.getenv("SECRET_KEY")
ENDPOINT = os.environ.get("ENDPOINT")
USERNAME = os.environ.get("USERNAME")
PASSWORD = os.environ.get("PASSWORD")
TOKEN = os.environ.get("TOKEN")
ORG_NAME = os.environ.get("ORG_NAME")
HOST = os.environ.get('HOST')


@app.post("/create_webhook")
def create_webhook():
    try:
        EVENTS = ["push", "repository", "member"]

        config = {
            "url": "https://{host}/{endpoint}".format(host=HOST, endpoint=ENDPOINT),
            "content_type": "json"
        }

        context = {
            'org': ORG_NAME,
            'name': 'web',
            'active': True,
            'events': EVENTS,
            'config': config
        }
        # create webhook using token
        headers = {'Authorization': 'Bearer ' + TOKEN,
                   "Accept": "application/vnd.github+json"}

        req = requests.post("https://api.github.com/orgs/{ORG}/hooks".format(ORG=ORG_NAME), json=context,
                            headers=headers)
        response = req.json()
        if response.get('message') == "Not Found":
            print("Exception: Incorrect Organization NAME.")
            print(response)
            pass
        if response.get('message') == "Bad credentials":
            print("Exception: Incorrect Token/BAD Login credentials.")
            print(response)
            pass
        return response
    except Exception as e:
        pass


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

    action = payload.get("action")

    print('action :', action)
    print('payload: ', payload)
    print('event_type :', event_type)

    if event_type == "create":
        return {'action': action, 'payload': payload, 'event_type': event_type}
    elif event_type == "delete":
        return {'action': action, 'payload': payload, 'event_type': event_type}
    else:
        return {'action': action, 'payload': payload, 'event_type': event_type}
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
