import asyncio
from backend.main import lifespan, app

async def test():
    try:
        async with lifespan(app):
            print("Lifespan executed successfully.")
    except Exception as e:
        import traceback
        traceback.print_exc()

asyncio.run(test())
