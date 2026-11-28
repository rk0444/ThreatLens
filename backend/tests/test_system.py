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




def _health_with_logs(logs, env=None, running=None):
    """Call /api/health against an in-memory DB holding the given (job, status, minutes_ago) runs."""
    import asyncio
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.database import models

    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    now = datetime.now(timezone.utc)
    for job, status, minutes_ago in logs:
        session.add(models.SchedulerLog(job_name=job, status=status, ran_at=(now - timedelta(minutes=minutes_ago)).replace(tzinfo=None)))
    session.commit()
    with mock.patch.dict(os.environ, {"OTX_API_KEY": "key", **(env or {})}), \
         mock.patch.dict(main.running_jobs, running or {}, clear=True):
        return asyncio.run(main.get_health(session))


def test_health_reports_feed_state_from_sync_runs_not_new_records():
    from datetime import datetime, timezone
    # A sync that finished recently is Live even though it brought no new CVEs (no CVE rows here at all)
    assert _health_with_logs([("NVD Sync", "Success", 3)])["nvd"]["status"] == "Live"
    # No successful sync for over twice the 15-minute interval
    assert _health_with_logs([("NVD Sync", "Success", 45)])["nvd"]["status"] == "Delayed"
    # The latest run failed, even though an older one succeeded
    assert _health_with_logs([("NVD Sync", "Success", 20), ("NVD Sync", "Failed", 2)])["nvd"]["status"] == "Down"
    # A run in progress
    running = {"NVD Sync": datetime.now(timezone.utc)}
    assert _health_with_logs([], running=running)["nvd"]["status"] == "Syncing"
    # Never run yet
    assert _health_with_logs([])["otx"]["status"] == "Waiting"


def test_health_otx_without_key_is_down_with_reason():
    otx = _health_with_logs([("OSINT Sync", "Success", 1)], env={"OTX_API_KEY": ""})["otx"]
    assert otx == {"status": "Down", "detail": "No key"}


def test_failed_otx_request_is_recorded_as_a_failed_sync():
    from backend.services import osint
    response = mock.Mock(status_code=403)
    with mock.patch.object(osint, "OTX_API_KEY", "key"), mock.patch.object(osint.requests, "get", return_value=response):
        try:
            osint.fetch_osint_alerts(mock.Mock())
            raised = False
        except RuntimeError:
            raised = True
    assert raised  # safe_run_job turns this into a Failed SchedulerLog row


if __name__ == "__main__":
    test_shutdown_waits_for_running_jobs_before_exiting()
    test_data_dir_moves_the_database()
    test_health_reports_feed_state_from_sync_runs_not_new_records()
    test_health_otx_without_key_is_down_with_reason()
    test_failed_otx_request_is_recorded_as_a_failed_sync()
    print("system tests passed")
