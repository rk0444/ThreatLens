# debug_scheduler.py — drop in E:\Project\ThreatLens\backend\
# Run: python debug_scheduler.py

from apscheduler.schedulers.background import BackgroundScheduler
import importlib, inspect, sqlite3, os

print("\n=== 1. IMPORT CHECK ===")
try:
    from services.nvd import ingest_nvd  # adjust import path if needed
    print(f"[OK] ingest_nvd imported: {inspect.getfile(ingest_nvd)}")
except Exception as e:
    print(f"[FAIL] Cannot import ingest_nvd: {e}")

print("\n=== 2. SCHEDULER INSTANCE CHECK ===")
try:
    from scheduler import scheduler  # adjust to wherever your scheduler lives
    jobs = scheduler.get_jobs()
    print(f"[OK] Scheduler found. Jobs registered: {len(jobs)}")
    for job in jobs:
        print(f"  - {job.id:30} next_run: {job.next_run_time}  func: {job.func_ref}")
    if not any("nvd" in j.id.lower() for j in jobs):
        print("[WARN] No NVD job found in registered jobs!")
except Exception as e:
    print(f"[FAIL] Cannot load scheduler: {e}")

print("\n=== 3. DATABASE LOG CHECK ===")
db_path = os.path.join("database", "threatlens.sqlite")
try:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scheduler_logs'")
    if cur.fetchone():
        cur.execute("SELECT job_name, status, message, ran_at FROM scheduler_logs ORDER BY ran_at DESC LIMIT 10")
        rows = cur.fetchall()
        print(f"[OK] scheduler_logs table exists. Last 10 entries:")
        for r in rows:
            print(f"  {r[3]}  {r[0]:20} [{r[1]}] {r[2]}")
        if not rows:
            print("  (empty — no jobs have ever logged)")
    else:
        print("[FAIL] scheduler_logs table does not exist in DB")
    conn.close()
except Exception as e:
    print(f"[FAIL] DB error: {e}")

print("\n=== 4. MANUAL TRIGGER TEST ===")
try:
    from services.nvd import ingest_nvd
    print("[INFO] Calling ingest_nvd() directly...")
    ingest_nvd()
    print("[OK] ingest_nvd() completed without exception")
except Exception as e:
    print(f"[FAIL] ingest_nvd() threw: {e}")
    import traceback; traceback.print_exc()