from fastapi import FastAPI
import uvicorn

app = FastAPI(title="unison-storage")

@app.get("/health")
def health():
    return {"status": "ok", "service": "unison-storage"}

@app.get("/ready")
def ready():
    # Future: check persistence / volumes
    return {"ready": True}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8082)
