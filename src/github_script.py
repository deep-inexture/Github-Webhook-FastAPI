import os
from github import Github, GithubException
from dotenv import load_dotenv
import datetime

load_dotenv()

TOKEN = os.environ.get("TOKEN")
github = Github(TOKEN)


def run_test_script():
    try:
        source_repo = github.get_repo("Testing-Demo-Deep-Organization/my_repo")

        target_repo = github.get_repo("Testing-Demo-Deep-Organization/my_dummy_repo")
        target_branch = "main"
        target_branch_obj = target_repo.get_branch(target_branch)

        no_of_test_branch = 2
        for i in range(1, no_of_test_branch + 1):
            target_branch = 'testing_' + str(i)
            target_repo.create_git_ref(ref='refs/heads/' + target_branch, sha=target_branch_obj.commit.sha)

            contents = source_repo.get_contents("")
            while contents:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    contents.extend(source_repo.get_contents(file_content.path))
                else:
                    if '.' in file_content.path and not '.git' in file_content.path:
                        new_file_name = file_content.path.replace('.', '_' + str(datetime.datetime.now()) + '.')
                    else:
                        new_file_name = file_content.path
                    content = file_content.decoded_content

                    target_repo.create_file(new_file_name, "committing ::: " + new_file_name, content=str(content),
                                            branch=target_branch)
                    print('file ::: ' + new_file_name + ' committed on branch ::: ' + target_branch)

    except GithubException as e:
        print('Exception Occurred ::: ' + str(e))
