import hmac
import os

from fastapi import Request, APIRouter
from fastapi import HTTPException
from github import Github
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(
    tags=["Users Webhooks Creations"]
)

WEBHOOK_SECRET = os.getenv("SECRET_KEY")
TOKEN = os.environ.get("TOKEN")

ENDPOINT = os.environ.get("USER_ENDPOINT")
ORG_NAME = os.environ.get("ORG_NAME")
HOST = os.environ.get('HOST')


@router.post("/create_users_webhook")
def create_webhook():
    try:
        EVENTS = ["member"]

        config = {
            "url": "https://{host}/{endpoint}".format(host=HOST, endpoint=ENDPOINT),
            "secret": WEBHOOK_SECRET,
            "content_type": "json"
        }

        # create webhook using token
        github = Github(TOKEN)
        org_obj = github.get_organization(ORG_NAME)
        webhook_obj = org_obj.create_hook(name='web', config=config, events=EVENTS, active=True)
        return "Users Webhook Created"

    except Exception as e:
        print(e)


# calculate hmac digest of payload with shared secret token
def calc_signature(payload):
    digest = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"), msg=payload, digestmod="sha1"
    ).hexdigest()
    return f"sha1={digest}"


@router.post("/user_updates")
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

    if event_type == "member" and action == "added" or action == "removed":
        print("Event = "+str(event_type)+"\nAction = "+str(action)+'\nPayload = '+str(payload))
