import hmac
import os

from fastapi import Request, APIRouter
from fastapi import HTTPException
from github import Github
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(
    tags=["Single Webhook Creation - 3 in 1"]
)

WEBHOOK_SECRET = os.getenv("SECRET_KEY")
TOKEN = os.environ.get("TOKEN")

ENDPOINT = os.environ.get("ENDPOINT")
ORG_NAME = os.environ.get("ORG_NAME")
HOST = os.environ.get('HOST')


@router.post("/create_webhook")
def create_webhook():
    try:
        EVENTS = ["push", "repository", "member"]

        config = {
            "url": "https://{host}/{endpoint}".format(host=HOST, endpoint=ENDPOINT),
            "secret": WEBHOOK_SECRET,
            "content_type": "json"
        }

        # create webhook using token
        github = Github(TOKEN)
        org_obj = github.get_organization(ORG_NAME)
        if org_obj:
            print("Already Exists")
            webhook_obj = org_obj.create_hook(name='web', config=config, events=EVENTS, active=True)
            return "Webhook Created"
        else:
            print(f"Enable to find Organization - {ORG_NAME}")

    except Exception as e:
        # Wrong ORGANIZATION NAME :
        # Exception : 404 {"message": "Not Found", "documentation_url": "https://docs.github.com/rest/reference/orgs#get-an-organization"}

        # WEBHOOK ALREADY EXISTS :
        # Exception : 422 {"message": "Validation Failed", "errors": [{"resource": "Hook", "code": "custom", "message": "Hook already exists on this organization"}], "documentation_url": "https://docs.github.com/rest/reference/orgs#create-an-organization-webhook"}

        # INCORRECT TOKEN
        # Exception : 401 {"message": "Bad credentials", "documentation_url": "https://docs.github.com/rest"}
        print(e)


# caclulate hmac digest of payload with shared secret token
def calc_signature(payload):
    digest = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"), msg=payload, digestmod="sha1"
    ).hexdigest()
    return f"sha1={digest}"


@router.post("/webhook")
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

    if event_type == "repository" and action == "publicized" or action == "privatized":
        print("Event = " + str(event_type) + "\nAction = " + str(action) + '\nPayload = ' + str(payload))
    if event_type == "repository" and action == "created" or action == "deleted":
        print("Event = " + str(event_type) + "\nAction = " + str(action) + '\nPayload = ' + str(payload))
