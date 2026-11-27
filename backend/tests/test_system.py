"""Run: .venv\\Scripts\\python backend\\tests\\test_system.py  (also works under pytest)."""
import os
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
from apscheduler.schedulers.background import BackgroundScheduler
from backend import main


def test_shutdown_waits_for_running_jobs_before_exiting():
    finished = []

    def slow_sync():
        time.sleep(1.0)
        finished.append("sync")

    def slow_manual_job():
        time.sleep(1.5)
        finished.append("manual")

    scheduler = BackgroundScheduler()
    scheduler.add_job(slow_sync, next_run_time=__import__("datetime").datetime.now())
    scheduler.start()
    time.sleep(0.3)  # the job is now running
    threading.Thread(name=main.JOB_THREAD, target=slow_manual_job).start()

    with mock.patch.object(main, "app_scheduler", scheduler), \
         mock.patch.object(main.threading, "Timer") as timer, \
         mock.patch.object(main.db.engine, "dispose") as dispose:
        assert main.shutdown_backend() == {"status": "stopped"}
    assert sorted(finished) == ["manual", "sync"]  # both finished before we returned
    assert not scheduler.running and dispose.called
    timer.assert_called_once_with(0.5, os._exit, args=(0,))  # exit only after all that


def test_data_dir_moves_the_database():
    data_dir = tempfile.mkdtemp()
    out = subprocess.run(
        [sys.executable, "-c", "from backend.database.db import DB_PATH; print(DB_PATH)"],
        cwd=ROOT, capture_output=True, text=True, env={**os.environ, "THREATLENS_DATA_DIR": data_dir},
    )
    assert out.stdout.strip() == os.path.join(data_dir, "threatlens.sqlite"), out.stderr


if __name__ == "__main__":
    test_shutdown_waits_for_running_jobs_before_exiting()
    test_data_dir_moves_the_database()
    print("system tests passed")
