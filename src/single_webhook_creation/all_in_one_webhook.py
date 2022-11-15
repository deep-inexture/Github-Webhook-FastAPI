import hmac
import os

from fastapi import Request, APIRouter
from fastapi import HTTPException
from github import Github, GithubException
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
        # Headers are, currently Access Token of your Github
        headers = {"Authorization": "Bearer " + TOKEN}

        # Primary Events for Github
        EVENTS = ["push", "repository", "member"]

        # Secondary Events for checking while updating the webhook
        # EVENTS = ["push", "repository"]

        # Configuration data required while using Pygithub libraries
        config = {
            "url": "{host}/{endpoint}".format(host=HOST, endpoint=ENDPOINT),
            "secret": WEBHOOK_SECRET,
            "content_type": "json"
        }

        # Below is a temp code for checking response through REST API call to compare with pyGithub call
        # =============================================================================================================
        # # Configurations required while creating webhook via requests Endpoint [Line No. :61]
        # data_for_create_webhook = {
        #     "config": config,
        #     "name": "web",
        #     "active": True,
        #     "events": EVENTS
        # }
        #
        # # Configurations required while updating webhook via requests Endpoint [Line No. :64]
        # data_for_update_webhook = {
        #     "active": True,
        #     "events": EVENTS
        # }
        #
        # # Create webhook via Github REST API call
        # response = requests.post(f"https://api.github.com/orgs/{ORG_NAME}/hooks",
        #                          data=json.dumps(data_for_create_webhook), headers=headers)
        # # Update webhook via Github REST API call
        # response = requests.patch(f"https://api.github.com/orgs/{ORG_NAME}/hooks/{387949674}",
        #                           data=json.dumps(data_for_update_webhook), headers=headers)
        # print(response.text)
        # return True
        # =============================================================================================================

        # Login to github via ACCESS TOKEN which will be required while using pyGithub commands
        github = Github(TOKEN)

        # Get an Organization object to perform further task of pyGithub
        org_obj = github.get_organization(ORG_NAME)
        if org_obj:
            print("Organization Available :::")

            # Get an object of all webhooks currently available on Github
            list_webhooks = org_obj.get_hooks()
            print('GET HOOKS RESPONSE\n', list_webhooks.get_page(0))
            if list_webhooks.get_page(0):
                print("Found some Webhooks, Checking for change :::")
                for webhook in list_webhooks:
                    # Fetch the webhook ID of the webhook found to access other element of that webhooks
                    hook_id = webhook.id

                    # Below the features avilable with get_hook by giving correct ID
                    # =================================================================================================
                    # print(org_obj.get_hook(hook_id).id)           GET THE WEBHOOK ID
                    # print(org_obj.get_hook(hook_id).name)         GET THE WEBHOOK NAME
                    # print(org_obj.get_hook(hook_id).url)          GET THE WEBHOOK URL
                    # print(org_obj.get_hook(id=hook_id).events)    GET THE WEBHOOK EVENTS
                    # print(org_obj.get_hook(id=hook_id).active)    GET THE WEBHOOK ACTIVE STATUS
                    # =================================================================================================

                    # Below is the Github REST API call to fetch webhook detail
                    # get_hook = requests.get(f'https://api.github.com/orgs/{ORG_NAME}/hooks/{hook_id}',
                    #                         headers=headers).json()

                    # Below tis the alternative of REST API call with pyGithub with event name get_hook
                    get_events = org_obj.get_hook(hook_id).events

                    # Fetch the events and check for updateds [If Any]
                    check_diff_in_events = list(set(get_events) ^ set(EVENTS))
                    if check_diff_in_events:
                        # Below is the REST API call for updating webhook details
                        # requests.patch(f"https://api.github.com/orgs/{ORG_NAME}/hooks/{hook_id}",
                        #                                headers=headers, data=json.dumps(new_updates_in_events))

                        # Updating the webhook via pyguhub library alternative of above code
                        update_hook = org_obj.edit_hook(id=hook_id, events=EVENTS, name="web",
                                                        config=config)
                        print('UPDATE HOOK RESPONSE\n', update_hook)
                        print('Webhook Updated Successfully :::')
                    else:
                        print('Everything is up-to-date :::')
            else:
                print("No Webhooks Found! Creating new Webhook :::")
                # Creating new webhook via pygithub library alternative of creation code written at top
                webhook_creation = org_obj.create_hook(name='web', config=config, events=EVENTS, active=True)
                print("CREATING WEBHOOK RESPONSE\n", webhook_creation)
                return "Webhook Created Successfully"
        else:
            print(f"Enable to find Organization - {ORG_NAME}", ' :::')
            return f"Enable to find Organization - {ORG_NAME}"

    except GithubException as e:
        print(e)


# caclulate hmac digest of payload with shared secret token
def calc_signature(payload):
    digest = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"), msg=payload, digestmod="sha1"
    ).hexdigest()
    return f"sha1={digest}"


@router.post("/webhook/github")
async def webhook_handler(request: Request):
    # verify webhook signature
    raw = await request.body()
    print(raw, 'rawrawrawrawrawrawrawraw')
    signature = request.headers.get("X-Hub-Signature")
    if signature != calc_signature(raw):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # handle events
    payload = await request.json()
    event_type = request.headers.get("X-Github-Event")

    action = payload.get("action")

    print('event_type :', event_type)
    print('action :', action)
    print('payload: ', payload)

    if event_type == "repository" and action == "publicized" or action == "privatized":
        print("Event = " + str(event_type) + "\nAction = " + str(action) + '\nPayload = ' + str(payload))
    if event_type == "repository" and action == "created" or action == "deleted":
        print("Event = " + str(event_type) + "\nAction = " + str(action) + '\nPayload = ' + str(payload))
    if event_type == "member" and action == "added" or action == "removed":
        print("Event = " + str(event_type) + "\nAction = " + str(action) + '\nPayload = ' + str(payload))
