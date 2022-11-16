import schedule
import threading

from src.single_webhook_creation import all_in_one_webhook


# Function that creates sub-thread for background Task and run till pending tasks get over
def run_continuously():
    # Creates new threading Event
    cease_continuous_run = threading.Event()

    class ScheduleThread(threading.Thread):
        @classmethod
        def run(cls):
            while not cease_continuous_run.is_set():
                schedule.run_pending()

    continuous_thread = ScheduleThread()
    continuous_thread.start()
    return cease_continuous_run


# Method that calls as a Job
def demo():
    """schedule this method"""
    create_job()


# Function that creates webhook as a part of Background Task
def create_job():
    response = all_in_one_webhook.create_webhook()


def start_scheduler():
    # *******************************************************************************************************
    # Used different library. For Testing
    # scheduler = BackgroundScheduler()
    # scheduler.add_job(demo, 'interval', seconds=3)
    # scheduler.start()
    # *******************************************************************************************************

    schedule.every(20).seconds.do(demo)
    # schedule.every(3).seconds.do(fetch_job)

    stop_run_continuously = run_continuously()
