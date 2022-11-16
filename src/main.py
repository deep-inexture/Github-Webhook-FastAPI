from fastapi import FastAPI
from .single_webhook_creation import all_in_one_webhook
from .multiple_webhook_creation import repository_webhook, commits_webhook, users_webhook
from src import scheduler

"""
Creates an Object of FastAPI Instance as app with some Title and Description while viewing in
Swagger or ReadDoc mode.
"""

tags_metadata = [
    {
        "name": "Single Webhook Creation - 3 in 1",
        "description": "Create Webhook for all 3 task into 1."
                       "Also Call webhook via only one endpoint '/webhook'"
    },
    {
        "name": "Repo Webhooks Creations",
        "description": "Create repository webhooks and its different events."
                       "Call this webhook with assigned endpoint '/repo"
    },
    {
        "name": "Commit Webhooks Creations",
        "description": "Create commits webhooks and its events for every pushes commits."
                       "Call this webhook with assigned endpoint '/commit"
    },
    {
        "name": "Users Webhooks Creations",
        "description": "Create users webhooks and its events for every user added | removed."
                       "Call this webhook with assigned endpoint '/user_updates"
    },
]

app = FastAPI(
    title='Github Webhook Implementation',
    description='Implementing webhook via github library in py and handle events via webhook endpoints on runtime',
    version='1.0.0',
    terms_of_service='',
    contact={
        'name': 'DEEP SHAH',
        'email': 'deep.inexture@gmail.com'
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    openapi_tags=tags_metadata
)


@app.on_event("startup")
async def startup_event():
    print("Reached...")
    read_root()


def read_root():
    try:
        scheduler.start_scheduler()
    except Exception as e:
        print(e)


"""Following command will call the routers and stored in different files for clean flow of project ."""
app.include_router(all_in_one_webhook.router)
app.include_router(repository_webhook.router)
app.include_router(commits_webhook.router)
app.include_router(users_webhook.router)
