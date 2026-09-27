from fastapi import FastAPI

app = FastAPI(title="Cloud Native Security Platform")


@app.get("/")
def root():
    return {
        "service": "security-demo-api",
        "status": "healthy"
    }


@app.get("/health")
def health():
    return {"status": "ok"}
