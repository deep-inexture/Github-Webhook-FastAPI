import threading
import schedule
import github_script


def run_threaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()


# Method that calls as a Job
def demo():
    """schedule this method"""
    create_job()


# Function that creates webhook as a part of Background Task
def create_job():
    response = github_script.run_test_script()


schedule.every(3).seconds.do(run_threaded, demo)
schedule.every(3).seconds.do(run_threaded, demo)
schedule.every(3).seconds.do(run_threaded, demo)
schedule.every(3).seconds.do(run_threaded, demo)
schedule.every(3).seconds.do(run_threaded, demo)

while True:
    schedule.run_pending()
