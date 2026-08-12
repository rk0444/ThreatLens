import sys
import os

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from database import db, models

db_session = next(db.get_db())

try:
    # Find assets to delete
    dummy_names = ['WS-PROD-01', 'TEST-ASSET']
    assets = db_session.query(models.Asset).filter(models.Asset.name.in_(dummy_names)).all()
    
    asset_ids = [a.id for a in assets]
    print(f"Found {len(asset_ids)} dummy assets to delete.")
    
    # Delete related incidents first
    incidents_deleted = db_session.query(models.Incident).filter(
        models.Incident.machine_id.in_(asset_ids)
    ).delete(synchronize_session=False)
    print(f"Deleted {incidents_deleted} dummy incidents.")
    
    # Delete assets
    assets_deleted = db_session.query(models.Asset).filter(models.Asset.name.in_(dummy_names)).delete(synchronize_session=False)
    print(f"Deleted {assets_deleted} dummy assets.")
    
    db_session.commit()
    print("Database cleanup completed successfully.")
except Exception as e:
    db_session.rollback()
    print(f"Error during cleanup: {e}")
finally:
    db_session.close()
